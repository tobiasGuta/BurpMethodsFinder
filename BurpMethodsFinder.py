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
                self.urlField.setText(sel)
                self.append_result("Loaded from proxy: " + sel)
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

        for m in methods:
            try:
                u = URL(url_text)
                host = u.getHost()
                port = u.getPort()
                proto = u.getProtocol()
                useHttps = (proto == 'https')
                # build default request and swap method token on request line
                req = self._helpers.buildHttpRequest(u)
                req_str = self._helpers.bytesToString(req)
                req_str = re.sub(r'^\s*(GET|POST|PUT|DELETE|OPTIONS|PATCH|HEAD)\b', m, req_str, flags=re.I)
                req_bytes = self._helpers.stringToBytes(req_str)
                service = self._helpers.buildHttpService(host, port if port != -1 else (443 if useHttps else 80), useHttps)

                start = time.time()
                resp = self._callbacks.makeHttpRequest(service, req_bytes)
                elapsed = (time.time() - start) * 1000.0
                if resp:
                    resp_bytes = resp.getResponse()
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
                else:
                    resp_bytes = None
                    resp_text = "No response"
                    code = "no-response"
                    total_len = 0
                    body_len = 0
                    line_short = "%s -> no response" % m
            except Exception as e:
                resp_bytes = None
                resp_text = "Error: " + str(e)
                code = "err"
                total_len = 0
                body_len = 0
                elapsed = 0.0
                line_short = "%s -> error: %s" % (m, str(e))

            # store details and add a row to the table (on EDT)
            def add_row(method=m, status=str(code), tlen=total_len, blen=body_len, tms=elapsed, reqs=req_str, respt=resp_text, svc_host=host, svc_port=(port if port != -1 else (443 if useHttps else 80)), svc_https=useHttps):
                try:
                    # store raw request/response bytes so Burp message editors can render them
                    self._test_rows.append({'method': method,
                                            'req': reqs, 'req_bytes': req_bytes,
                                            'resp': respt, 'resp_bytes': resp_bytes,
                                            'code': status, 'total': tlen, 'body': blen, 'time': tms,
                                            'svc_host': svc_host, 'svc_port': svc_port, 'svc_https': svc_https})
                    self.tableModel.addRow([method, status, tlen, blen, ("%.1f ms" % tms)])
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
