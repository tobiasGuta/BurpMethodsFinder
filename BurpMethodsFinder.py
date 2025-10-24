# -*- coding: utf-8 -*-
# BurpMethodsFinder.py
# Jython 2.7 - Burp extension: HTTP Method Tester (load URL from Proxy history, test multiple methods)
# Drop into Burp Extender with Jython standalone JAR configured.

from burp import IBurpExtender, ITab
from java.io import PrintWriter
from javax import swing
from java.awt import Dimension, EventQueue, Font, BorderLayout
from java.awt.event import ActionListener, MouseAdapter
from javax.swing import JOptionPane, JScrollPane
from java.net import URL
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from javax.swing import JTable
from java.lang import String
import re
import threading
import time

class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpMethodsFinder")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # storage for test rows (one dict per method test)
        self._test_rows = []

        # build UI on EDT
        def create_ui():
            try:
                self.initUI()
                self._callbacks.addSuiteTab(self)
                self.log("BurpMethodsFinder loaded.")
            except Exception as e:
                self.err("UI init error: " + str(e))
        EventQueue.invokeLater(create_ui)

    # UI
    def initUI(self):
        # use BorderLayout so center area expands to fill available space
        self.panel = swing.JPanel()
        self.panel.setLayout(BorderLayout())

        # top: title + controls in a small horizontal box
        top = swing.JPanel()
        top.setLayout(swing.BoxLayout(top, swing.BoxLayout.X_AXIS))
        top.add(swing.JLabel("HTTP Method Tester"))
        top.add(self.urlField if hasattr(self, 'urlField') else swing.JTextField("https://example.com/path"))
        # ensure existing controls (if already created) are used; otherwise create buttons
        try:
            self.urlField.setMaximumSize(Dimension(700, 26))
        except:
            self.urlField = swing.JTextField("https://example.com/path")
            self.urlField.setMaximumSize(Dimension(700, 26))
        try:
            self.loadProxyBtn
        except:
            self.loadProxyBtn = swing.JButton("Load from Proxy", actionPerformed=self._load_from_proxy_history)
        try:
            self.testBtn
        except:
            self.testBtn = swing.JButton("Test Methods", actionPerformed=self._on_test_methods)
        top.add(self.urlField)
        top.add(self.loadProxyBtn)
        top.add(self.testBtn)

        # results TABLE (one row per method)
        self.tableModel = DefaultTableModel(0, 5)
        self.tableModel.setColumnIdentifiers(["Method", "Status", "Total (B)", "Body (B)", "Time"])
        self.resultsTable = JTable(self.tableModel)
        self.resultsTable.setAutoCreateRowSorter(True)
        tableScroll = JScrollPane(self.resultsTable)
        tableScroll.setMinimumSize(Dimension(200, 120))

        # Request / Response viewers (left = request, right = response)
        # Use Burp's built-in message editors (provides colored/syntax view like Repeater)
        self.reqEditor = self._callbacks.createMessageEditor(None, False)
        reqComp = self.reqEditor.getComponent()
        reqScroll = JScrollPane(reqComp)
        reqScroll.setMinimumSize(Dimension(100, 100))

        self.respEditor = self._callbacks.createMessageEditor(None, False)
        respComp = self.respEditor.getComponent()
        respScroll = JScrollPane(respComp)
        respScroll.setMinimumSize(Dimension(100, 100))

        # horizontal split between request and response (like Repeater panes)
        split = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT, reqScroll, respScroll)
        split.setResizeWeight(0.5)
        split.setContinuousLayout(True)
        split.setOneTouchExpandable(True)
        split.setMinimumSize(Dimension(200, 200))

        # vertical split: top = table, bottom = request/response split
        main_split = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT, tableScroll, split)
        main_split.setResizeWeight(0.35)   # give the table ~35% of vertical space initially
        main_split.setContinuousLayout(True)
        main_split.setOneTouchExpandable(True)
        main_split.setMinimumSize(Dimension(400, 300))

        # assemble into BorderLayout center (top goes to NORTH)
        self.panel.add(top, BorderLayout.NORTH)
        self.panel.add(main_split, BorderLayout.CENTER)

        # center dividers after UI realized
        def center_dividers():
            try:
                main_split.setDividerLocation(0.35)
            except:
                pass
            try:
                split.setDividerLocation(0.5)
            except:
                pass
        EventQueue.invokeLater(center_dividers)

        # selection listener: update request/response when a table row is selected
        class SelListener(ListSelectionListener):
            def __init__(self, outer):
                self.outer = outer
            def valueChanged(self, ev):
                try:
                    sel = self.outer.resultsTable.getSelectedRow()
                    if sel == -1:
                        return
                    modelRow = self.outer.resultsTable.convertRowIndexToModel(sel)
                    item = self.outer._test_rows[modelRow]
                    # show raw bytes in Burp message editors (isRequest True for request pane)
                    req_bytes = item.get('req_bytes')
                    resp_bytes = item.get('resp_bytes')

                    # debug log (type/length) to help diagnose why response isn't showing
                    try:
                        lreq = len(req_bytes) if req_bytes is not None else 0
                    except:
                        lreq = "?"
                    try:
                        lresp = len(resp_bytes) if resp_bytes is not None else 0
                    except:
                        lresp = "?"
                    try:
                        self.outer.stdout.println("[MethodsTester] selection -> req_bytes=%s resp_bytes=%s" % (str(lreq), str(lresp)))
                    except:
                        pass

                    # run editor updates on EDT to avoid threading/UI timing issues
                    def update_editors():
                        try:
                            try:
                                self.outer.reqEditor.setMessage(req_bytes, True)
                            except:
                                self.outer.reqEditor.setMessage(None, True)
                            try:
                                self.outer.respEditor.setMessage(resp_bytes, False)
                            except:
                                self.outer.respEditor.setMessage(None, False)
                        except:
                            pass
                    EventQueue.invokeLater(update_editors)
                except:
                    pass

        self.resultsTable.getSelectionModel().addListSelectionListener(SelListener(self))

        # popup menu on table rows: send request to Repeater
        popup = swing.JPopupMenu()
        # small ActionListener implementation (works in Jython)
        class RepeaterAction(ActionListener):
            def __init__(self, outer, editor=False):
                self.outer = outer
                self.editor = editor
            def actionPerformed(self, ev):
                try:
                    if self.editor:
                        self.outer._send_editor_request_to_repeater()
                    else:
                        self.outer._send_selected_request_to_repeater()
                except:
                    pass

        sendReqItem = swing.JMenuItem("Send selected request to Repeater")
        sendReqItem.addActionListener(RepeaterAction(self, False))
        popup.add(sendReqItem)

        # also offer an option to send the request currently shown in the editor
        sendEditorItem = swing.JMenuItem("Send editor request to Repeater")
        sendEditorItem.addActionListener(RepeaterAction(self, True))
        popup.add(sendEditorItem)

        # attach mouse listener to show popup on right-click
        class TablePopupListener(MouseAdapter):
            def __init__(self, outer):
                self.outer = outer
            def maybeShowPopup(self, ev):
                if ev.isPopupTrigger():
                    # select row under mouse
                    row = self.outer.resultsTable.rowAtPoint(ev.getPoint())
                    if row != -1:
                        self.outer.resultsTable.setRowSelectionInterval(row, row)
                    popup.show(ev.getComponent(), ev.getX(), ev.getY())
            def mousePressed(self, ev): self.maybeShowPopup(ev)
            def mouseReleased(self, ev): self.maybeShowPopup(ev)

        self.resultsTable.addMouseListener(TablePopupListener(self))

        # also add popup to the request editor component so you can send the currently shown request
        try:
            reqComp.addMouseListener(TablePopupListener(self))
            # reuse same popup but change menu text so user knows it's from editor
            # (the same action will send the current reqEditor message)
        except:
            pass

    def getTabCaption(self):
        return "Methods Tester"

    def getUiComponent(self):
        return self.panel

    # Button handlers
    def _load_from_proxy_history(self, event):
        try:
            entries = self._callbacks.getProxyHistory()
            choices = []
            seen = set()
            # collect unique URLs from proxy history (most recent first)
            for e in reversed(entries):
                try:
                    url = self._helpers.analyzeRequest(e).getUrl()
                    s = str(url)
                    if s not in seen:
                        seen.add(s)
                        choices.append(s)
                except:
                    pass
            if not choices:
                JOptionPane.showMessageDialog(self.panel, "No proxy history available.", "Info", JOptionPane.INFORMATION_MESSAGE)
                return
            sel = JOptionPane.showInputDialog(self.panel, "Select proxy entry", "Load from Proxy", JOptionPane.QUESTION_MESSAGE, None, choices, choices[0])
            if sel:
                # set URL field
                self.urlField.setText(sel)

                # find the matching proxy entry (most recent first) and import full raw request/response
                try:
                    matched = None
                    for e in reversed(entries):
                        try:
                            url = self._helpers.analyzeRequest(e).getUrl()
                            if str(url) == sel:
                                matched = e
                                break
                        except:
                            pass
                    if matched is not None:
                        try:
                            req_bytes = matched.getRequest()
                            resp_bytes = matched.getResponse()
                            # populate Burp message editors with full raw (headers + body)
                            try:
                                self.reqEditor.setMessage(req_bytes, True)
                            except:
                                try:
                                    self.reqEditor.setMessage(None, True)
                                except:
                                    pass
                            try:
                                self.respEditor.setMessage(resp_bytes, False)
                            except:
                                try:
                                    self.respEditor.setMessage(None, False)
                                except:
                                    pass
                            self.append_result("Loaded full request/response from proxy: " + sel)
                        except Exception as ex:
                            # fallback: only notify that URL was loaded
                            self.append_result("Loaded from proxy (request/response not available): " + sel + " (" + str(ex) + ")")
                    else:
                        self.append_result("Loaded from proxy: " + sel)
                except Exception as e:
                    # ensure we at least set the URL and log the error
                    self.append_result("Loaded from proxy (error retrieving messages): " + sel + " (" + str(e) + ")")
        except Exception as e:
             self.err("Load from proxy failed: " + str(e))
             self.append_result("Load from proxy failed: " + str(e))

    def _on_test_methods(self, event):
        url_text = str(self.urlField.getText()).strip()
        if not url_text:
            JOptionPane.showMessageDialog(self.panel, "Enter a URL first.", "Error", JOptionPane.ERROR_MESSAGE)
            return
        # run tests in background thread
        t = threading.Thread(target=self._run_tests, args=(url_text,))
        t.setDaemon(True)
        t.start()

    # core testing logic
    def _run_tests(self, url_text):
        methods = ['GET', 'HEAD', 'POST', 'PUT', 'OPTIONS', 'PATCH', 'DELETE']
        # simple status message to stdout
        try:
            self.stdout.println("[BurpMethodsFinder] Starting method tests for: " + url_text)
        except:
            pass

        # clear previous rows
        def clear_rows():
            try:
                self.tableModel.setRowCount(0)
                self._test_rows = []
            except:
                pass
        EventQueue.invokeLater(clear_rows)

        # capture a template request (if the user imported one into the editor) so we preserve headers/body
        try:
            template_req_bytes = None
            try:
                template_req_bytes = self.reqEditor.getMessage()
            except:
                template_req_bytes = None
        except:
            template_req_bytes = None

        # DEBUG: show short preview of the imported template (so we can compare with what we send)
        try:
            if template_req_bytes is not None:
                try:
                    tpl_preview = self._helpers.bytesToString(template_req_bytes)[:400]
                except:
                    tpl_preview = repr(template_req_bytes)[:400]
                try:
                    has_auth = bool(re.search(r'(?im)^Authorization:\s*', tpl_preview))
                except:
                    has_auth = False
                self.stdout.println("[MethodsTester][DEBUG] template preview (first 400 chars): %s" % tpl_preview)
                self.stdout.println("[MethodsTester][DEBUG] template has Authorization header: %s" % str(has_auth))
        except:
            pass

        for m in methods:
            try:
                u = URL(url_text)
                host = u.getHost()
                port = u.getPort()
                proto = u.getProtocol()
                useHttps = (proto == 'https')

                # build request bytes:
                # - if the user has loaded a request into the editor, use it as a template and only swap the method (and update Host / Content-Length)
                # - otherwise fall back to building a fresh request from the URL
                req_bytes = None
                req_str = None
                try:
                    if template_req_bytes:
                        # Prefer preserving the original raw request exactly and only swap the verb on the request-line.
                        # This avoids modifying HTTP version, headers or body bytes (Content-Length, Transfer-Encoding, etc.)
                        try:
                            tmp_str = self._helpers.bytesToString(template_req_bytes)
                            # replace only the first method token on the request-line
                            req_str = re.sub(r'^(GET|POST|PUT|DELETE|OPTIONS|PATCH|HEAD)\b', m, tmp_str, flags=re.I)
                            req_bytes = self._helpers.stringToBytes(req_str)
                        except Exception:
                            # if the simple method-replace fails, fall back to the original rebuild logic
                            analyzed_template = None
                            try:
                                analyzed_template = self._helpers.analyzeRequest(template_req_bytes)
                            except:
                                analyzed_template = None

                            if analyzed_template is not None:
                                body_offset = analyzed_template.getBodyOffset()
                            else:
                                tb = self._helpers.bytesToString(template_req_bytes)
                                idx = tb.find("\r\n\r\n")
                                body_offset = idx + 4 if idx != -1 else len(tb)

                            headers_part = self._helpers.bytesToString(template_req_bytes[:body_offset])
                            body_part_bytes = template_req_bytes[body_offset:] if body_offset < len(template_req_bytes) else None

                            path = u.getFile()
                            if not path:
                                path = "/"
                            first_line_end = headers_part.find("\r\n")
                            if first_line_end == -1:
                                first_line_end = len(headers_part)
                            first_line = headers_part[:first_line_end]
                            parts = first_line.split()
                            version = parts[2] if len(parts) >= 3 else "HTTP/1.1"
                            new_req_line = "%s %s %s" % (m, path, version)
                            headers_rest = headers_part[first_line_end+2:] if first_line_end+2 <= len(headers_part) else ""

                            host_header_value = host
                            effective_port = port if port != -1 else (443 if useHttps else 80)
                            if (useHttps and effective_port != 443) or (not useHttps and effective_port != 80):
                                host_header_value = "%s:%d" % (host, effective_port)
                            if re.search(r'(?im)^Host:\s*', headers_rest):
                                headers_rest = re.sub(r'(?im)^Host:.*', "Host: " + host_header_value, headers_rest, count=1)
                            else:
                                headers_rest = "Host: " + host_header_value + ("\r\n" + headers_rest if headers_rest.strip() else "\r\n")

                            if body_part_bytes is not None:
                                if re.search(r'(?im)^Content-Length:\s*\d+', headers_rest):
                                    headers_rest = re.sub(r'(?im)^Content-Length:\s+\d+', "Content-Length: %d" % len(body_part_bytes), headers_rest, count=1)
                                elif not re.search(r'(?im)^Transfer-Encoding:\s*chunked', headers_rest):
                                    headers_rest = headers_rest.rstrip() + "\r\nContent-Length: %d\r\n" % len(body_part_bytes)

                            req_str = new_req_line + "\r\n" + headers_rest + "\r\n"
                            try:
                                req_bytes = self._helpers.stringToBytes(req_str)
                                if body_part_bytes:
                                    req_bytes = req_bytes + body_part_bytes
                            except:
                                try:
                                    tmp_str = self._helpers.bytesToString(template_req_bytes)
                                    req_str = re.sub(r'^\s*(GET|POST|PUT|DELETE|OPTIONS|PATCH|HEAD)\b', m, tmp_str, flags=re.I)
                                    req_bytes = self._helpers.stringToBytes(req_str)
                                except:
                                    req_bytes = template_req_bytes
                    else:
                        # no template: original behavior (build minimal request from URL)
                        req = self._helpers.buildHttpRequest(u)
                        req_str = self._helpers.bytesToString(req)
                        req_str = re.sub(r'^\s*(GET|POST|PUT|DELETE|OPTIONS|PATCH|HEAD)\b', m, req_str, flags=re.I)
                        req_bytes = self._helpers.stringToBytes(req_str)
                except Exception:
                    # on any failure above, fall back to simple builder
                    try:
                        req = self._helpers.buildHttpRequest(u)
                        req_str = self._helpers.bytesToString(req)
                        req_str = re.sub(r'^\s*(GET|POST|PUT|DELETE|OPTIONS|PATCH|HEAD)\b', m, req_str, flags=re.I)
                        req_bytes = self._helpers.stringToBytes(req_str)
                    except Exception as e:
                        raise

                service = self._helpers.buildHttpService(host, port if port != -1 else (443 if useHttps else 80), useHttps)

                # DEBUG: show the exact request bytes we will send (short preview) and whether Authorization exists
                try:
                    if req_bytes is not None:
                        try:
                            req_preview = self._helpers.bytesToString(req_bytes)[:400]
                        except:
                            req_preview = repr(req_bytes)[:400]
                        try:
                            req_has_auth = bool(re.search(r'(?im)^Authorization:\s*', req_preview))
                        except:
                            req_has_auth = False
                        self.stdout.println("[MethodsTester][DEBUG] sending request preview (first 400 chars): %s" % req_preview)
                        self.stdout.println("[MethodsTester][DEBUG] sending request has Authorization header: %s" % str(req_has_auth))
                except:
                    pass

                start = time.time()
                resp = None
                last_exc = None
                try:
                    resp = self._callbacks.makeHttpRequest(service, req_bytes)
                except Exception as e:
                    last_exc = e

                # if primary call returned no response (or empty), try fallback overloads and log debug info
                try:
                    got_bytes = None
                    if resp is not None:
                        try:
                            got_bytes = resp.getResponse()
                        except:
                            got_bytes = None

                    if resp is None or got_bytes is None or (hasattr(got_bytes, "__len__") and len(got_bytes) == 0):
                        try:
                            self.stdout.println("[MethodsTester] primary makeHttpRequest returned empty/None, trying fallbacks (host/port overload). last_exc=%s" % str(last_exc))
                        except:
                            pass
                        try:
                            # try older overload: (host, port, useHttps, request)
                            resp = self._callbacks.makeHttpRequest(host, (port if port != -1 else (443 if useHttps else 80)), useHttps, req_bytes)
                        except Exception as e2:
                            last_exc = e2
                            try:
                                # final fallback: try with explicit IHttpService built again
                                svc2 = self._helpers.buildHttpService(host, (port if port != -1 else (443 if useHttps else 80)), useHttps)
                                resp = self._callbacks.makeHttpRequest(svc2, req_bytes)
                            except Exception as e3:
                                last_exc = e3

                except Exception as dbg_e:
                    try:
                        self.stderr.println("[MethodsTester] makeHttpRequest fallback debugging error: " + str(dbg_e))
                    except:
                        pass

                elapsed = (time.time() - start) * 1000.0

                # resp can be either:
                #  - an IHttpRequestResponse (has getResponse()),
                #  - or a raw byte container returned by some overloads (array.array / bytes / Java byte[]).
                resp_raw = None
                try:
                    if resp is None:
                        resp_raw = None
                    elif hasattr(resp, "getResponse"):
                        # normal Burp response object
                        try:
                            resp_raw = resp.getResponse()
                        except:
                            resp_raw = None
                    else:
                        # resp itself may already be raw bytes (array.array, buffer, Java byte[], etc.)
                        resp_raw = resp
                except:
                    resp_raw = None

                try:
                    self.stdout.println("[MethodsTester][DEBUG] resp container type=%s resp_raw_type=%s" % (str(type(resp)), str(type(resp_raw))))
                except:
                    pass

                # DEBUG: inspect raw response object returned by makeHttpRequest (attempt to preview without consuming)
                try:
                    if resp_raw is None:
                        self.stdout.println("[MethodsTester][DEBUG] resp_raw is None")
                    else:
                        try:
                            if hasattr(resp_raw, "tostring"):
                                s = resp_raw.tostring()
                                self.stdout.println("[MethodsTester][DEBUG] resp_raw.tostring() len=%s preview=%s" % (str(len(s)), repr(s[:200])))
                            elif hasattr(resp_raw, "tobytes"):
                                s = resp_raw.tobytes()
                                self.stdout.println("[MethodsTester][DEBUG] resp_raw.tobytes() len=%s preview=%s" % (str(len(s)), repr(s[:200])))
                            else:
                                try:
                                    s = self._helpers.bytesToString(resp_raw)
                                    self.stdout.println("[MethodsTester][DEBUG] helpers.bytesToString len=%s preview=%s" % (str(len(s)), repr(s[:200])))
                                except:
                                    self.stdout.println("[MethodsTester][DEBUG] resp_raw repr=%s" % repr(resp_raw)[:200])
                        except Exception as exdbg:
                            self.stdout.println("[MethodsTester][DEBUG] resp_raw inspection error: %s" % str(exdbg))
                except:
                    pass

                # normalize resp_raw -> resp_bytes (Java byte[]) for Burp helpers/editors
                resp_bytes = None
                try:
                    if resp_raw is not None:
                        # common types: array.array, Python str, Java byte[], helpers' types
                        try:
                            # array.array (Jython) / bytes: tostring() or tobytes()
                            if hasattr(resp_raw, "tostring"):
                                resp_bytes = self._helpers.stringToBytes(resp_raw.tostring())
                            elif hasattr(resp_raw, "tobytes"):
                                resp_bytes = self._helpers.stringToBytes(resp_raw.tobytes())
                            else:
                                # try helpers.bytesToString -> stringToBytes (handles Java byte[] and other types)
                                try:
                                    resp_bytes = self._helpers.stringToBytes(self._helpers.bytesToString(resp_raw))
                                except:
                                    # fallback: stringify then convert
                                    resp_bytes = self._helpers.stringToBytes(str(resp_raw))
                        except Exception:
                            # if conversion fails, keep resp_raw if it already is a Java byte[]
                            try:
                                resp_bytes = resp_raw
                            except:
                                resp_bytes = None
                except:
                    resp_bytes = None

                # debug: compute a useful length for many types (Java byte[], array.array, str, etc.)
                try:
                    if resp_bytes is None:
                        rlen = "None"
                    else:
                        try:
                            rlen = len(resp_bytes)
                        except:
                            try:
                                rlen = len(self._helpers.bytesToString(resp_bytes))
                            except:
                                rlen = "?"
                    self.stdout.println("[MethodsTester] makeHttpRequest result -> resp_obj=%s resp_len=%s last_exc=%s" % (str(type(resp)), str(rlen), str(last_exc)))
                except:
                    pass

                analyzed = self._helpers.analyzeResponse(resp_bytes) if resp_bytes is not None else None
                code = analyzed.getStatusCode() if analyzed is not None else -1
                total_len = len(resp_bytes) if resp_bytes is not None else 0
                body_len = 0
                if analyzed is not None:
                    body_offset = analyzed.getBodyOffset()
                    body_bytes = resp_bytes[body_offset:] if resp_bytes is not None else None
                    body_len = len(body_bytes) if body_bytes is not None else 0
                # convert response bytes to a displayable string (headers+body)
                try:
                    resp_text = self._helpers.bytesToString(resp_bytes) if resp_bytes is not None else ""
                except:
                    resp_text = "<binary response> ({} bytes)".format(total_len)
                line_short = "%s -> %s  | total=%d  body=%d  | time=%.1f ms" % (m, str(code), total_len, body_len, elapsed)
            except Exception as e:
                resp_bytes = None
                resp_text = "Error: " + str(e)
                code = "err"
                total_len = 0
                body_len = 0
                elapsed = 0.0
                line_short = "%s -> error: %s" % (m, str(e))

            # store details and add a row to the table (on EDT)
            def add_row(method=m, status=str(code), tlen=total_len, blen=body_len, tms=elapsed, reqs=req_str, reqb=req_bytes, respb=resp_bytes, respt=resp_text, svc_host=host, svc_port=(port if port != -1 else (443 if useHttps else 80)), svc_https=useHttps):
                try:
                    # store raw request/response bytes so Burp message editors can render them
                    self._test_rows.append({'method': method,
                                            'req': reqs, 'req_bytes': reqb,
                                            'resp': respt, 'resp_bytes': respb,
                                            'code': status, 'total': tlen, 'body': blen, 'time': tms,
                                            'svc_host': svc_host, 'svc_port': svc_port, 'svc_https': svc_https})
                    self.tableModel.addRow([method, status, tlen, blen, ("%.1f ms" % tms)])

                    # select the newly added row and update editors so request/response are visible immediately
                    try:
                        last_model_index = self.tableModel.getRowCount() - 1
                        try:
                            view_index = self.resultsTable.convertRowIndexToView(last_model_index)
                        except:
                            # if convertRowIndexToView not available or fails, just use model index
                            view_index = last_model_index
                        self.resultsTable.setRowSelectionInterval(view_index, view_index)
                    except:
                        pass

                    # populate editors with the raw bytes (if available)
                    try:
                        self.reqEditor.setMessage(reqb, True)
                    except:
                        try:
                            self.reqEditor.setMessage(None, True)
                        except:
                            pass
                    try:
                        self.respEditor.setMessage(respb, False)
                    except:
                        try:
                            self.respEditor.setMessage(None, False)
                        except:
                            pass

                except Exception as ex:
                    try:
                        self.stderr.println("Add row failed: " + str(ex))
                    except:
                        pass
            EventQueue.invokeLater(add_row)

        try:
            self.stdout.println("[BurpMethodsFinder] Method tests completed for: " + url_text)
        except:
            pass

    # helpers
    def append_result(self, text):
        # no local GUI text area for generic messages any more; print to stdout
        try:
            self.stdout.println(str(text))
        except:
            try:
                self.stderr.println(str(text))
            except:
                pass

    def log(self, msg):
        try:
            self.stdout.println("[BurpMethodsFinder] " + str(msg))
        except:
            pass

    def err(self, msg):
        try:
            self.stderr.println("[BurpMethodsFinder] " + str(msg))
        except:
            pass

    # send selected table request to Repeater
    def _send_selected_request_to_repeater(self):
        try:
            sel = self.resultsTable.getSelectedRow()
            if sel == -1:
                JOptionPane.showMessageDialog(self.panel, "No row selected.", "Info", JOptionPane.INFORMATION_MESSAGE)
                return
            modelRow = self.resultsTable.convertRowIndexToModel(sel)
            item = self._test_rows[modelRow]
            req_bytes = item.get('req_bytes')
            if not req_bytes:
                JOptionPane.showMessageDialog(self.panel, "No request available for this row.", "Error", JOptionPane.ERROR_MESSAGE)
                return
            host = item.get('svc_host')
            port = int(item.get('svc_port'))
            useHttps = bool(item.get('svc_https'))

            sent = False
            last_exc = None
            try:
                # prefer the IHttpService overload
                svc = self._helpers.buildHttpService(host, port, useHttps)
                self._callbacks.sendToRepeater(svc, req_bytes)
                sent = True
            except Exception as e:
                last_exc = e
                # fallback to other known overloads
                try:
                    self._callbacks.sendToRepeater(host, port, useHttps, req_bytes, None)
                    sent = True
                except Exception as e2:
                    last_exc = e2
                    try:
                        self._callbacks.sendToRepeater(host, port, useHttps, req_bytes)
                        sent = True
                    except Exception as e3:
                        last_exc = e3

            if sent:
                self.append_result("Sent request to Repeater: %s:%s" % (host, port))
            else:
                raise last_exc or Exception("Unknown sendToRepeater failure")
        except Exception as e:
            self.err("Send to Repeater failed: " + str(e))
            try:
                JOptionPane.showMessageDialog(self.panel, "Send to Repeater failed: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
            except:
                pass

    # send currently displayed request in the request editor to Repeater
    def _send_editor_request_to_repeater(self):
        try:
            msg = self.reqEditor.getMessage()
            if msg is None:
                JOptionPane.showMessageDialog(self.panel, "No request in editor.", "Info", JOptionPane.INFORMATION_MESSAGE)
                return

            host = None
            port = None
            useHttps = False

            # try to derive host/port/protocol from the request via helpers
            try:
                analyzed = self._helpers.analyzeRequest(msg)
                url = analyzed.getUrl()
                host = url.getHost()
                port = url.getPort()
                proto = url.getProtocol()
                useHttps = (proto == 'https')
                if port == -1:
                    port = 443 if useHttps else 80
            except:
                # fallback: parse Host header from raw request bytes
                try:
                    req_text = self._helpers.bytesToString(msg)
                    m = re.search(r'(?im)^Host:\s*([^:\r\n]+)(?::(\d+))?', req_text)
                    if m:
                        host = m.group(1)
                        port = int(m.group(2)) if m.group(2) else 80
                        useHttps = (port == 443)
                except:
                    pass

            if not host:
                JOptionPane.showMessageDialog(self.panel, "Could not determine host/port from editor request.", "Error", JOptionPane.ERROR_MESSAGE)
                return

            sent = False
            last_exc = None
            try:
                svc = self._helpers.buildHttpService(host, int(port), bool(useHttps))
                self._callbacks.sendToRepeater(svc, msg)
                sent = True
            except Exception as e:
                last_exc = e
                try:
                    # try other overloads
                    self._callbacks.sendToRepeater(host, int(port), bool(useHttps), msg, None)
                    sent = True
                except Exception as e2:
                    last_exc = e2
                    try:
                        self._callbacks.sendToRepeater(host, int(port), bool(useHttps), msg)
                        sent = True
                    except Exception as e3:
                        last_exc = e3

            if sent:
                self.append_result("Sent editor request to Repeater: %s:%s" % (host, port))
            else:
                raise last_exc or Exception("Unknown sendToRepeater failure")
        except Exception as e:
            self.err("Send editor to Repeater failed: " + str(e))
            try:
                JOptionPane.showMessageDialog(self.panel, "Send to Repeater failed: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
            except:
                pass
