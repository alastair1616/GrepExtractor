# burp imports
from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IExtensionHelpers
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import ITab
import re

# java imports
from javax.swing import JMenuItem, JPanel, JLabel, JScrollPane, JTextArea, BoxLayout, JButton, JCheckBox, JTextField
from java.awt import BorderLayout
import threading

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        # Credit to https://cornerpirate.com/2018/07/24/grep-extractor-a-burp-extender/
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Grep Extractor")
        self.callbacks.registerContextMenuFactory(self)

        # Create the custom tab
        self.createTab()

        # Add the custom tab to Burp's UI
        self.callbacks.addSuiteTab(self)
        return

    def createTab(self):
        # Create main panel
        self.tab = JPanel(BorderLayout())

        # Create a text area for displaying extracted data
        self.text_area = JTextArea()
        self.text_area.setLineWrap(True)
        self.text_area.setWrapStyleWord(True)

        # Add a scroll pane to the text area
        scroll_pane = JScrollPane(self.text_area)

        # Create a panel for checkboxes, text field, and buttons
        control_panel = JPanel()
        control_panel.setLayout(BoxLayout(control_panel, BoxLayout.Y_AXIS))

        # Add regex input field
        self.regex_field = JTextField(r'\d{8}', 20)
        control_panel.add(JLabel("Regex Pattern:"))
        control_panel.add(self.regex_field)

        # Add checkboxes
        self.req_checkbox = JCheckBox("Request")
        self.res_checkbox = JCheckBox("Response")
        self.req_checkbox.setSelected(True)  # Default to request being checked
        self.res_checkbox.setSelected(True)  # Default to response being checked
        control_panel.add(self.req_checkbox)
        control_panel.add(self.res_checkbox)

        # Add clear button
        clear_button = JButton("Clear Output")
        clear_button.addActionListener(self.clearOutput)
        control_panel.add(clear_button)

        # Add the control panel to the main panel
        self.tab.add(control_panel, BorderLayout.NORTH)
        self.tab.add(scroll_pane, BorderLayout.CENTER)

    def getTabCaption(self):
        # This is the name of the tab
        return "Grep Extractor"

    def getUiComponent(self):
        # This is the UI component to be displayed in the tab
        return self.tab

    def createMenuItems(self, invocation):
        menu_list = []
        menu_list.append(JMenuItem("Grep Extractor", None, actionPerformed=lambda x, inv=invocation: self.startThreaded(self.grep_extract, invocation)))
        return menu_list

    def startThreaded(self, func, *args):
        th = threading.Thread(target=func, args=args)
        th.start()

    def grep_extract(self, invocation):
        http_traffic = invocation.getSelectedMessages()
        pattern = self.regex_field.getText()  # Get the regex pattern from the text field
        for traffic in http_traffic:
            if traffic.getResponse() is not None:
                req = traffic.getRequest().tostring()
                res = traffic.getResponse().tostring()

                if self.req_checkbox.isSelected():
                    match = re.search(pattern, req)
                    if match:
                        extracted = match.group()
                        self.updateOutput(extracted)

                if self.res_checkbox.isSelected():
                    match = re.search(pattern, res)
                    if match:
                        extracted = match.group()
                        self.updateOutput(extracted)

    def updateOutput(self, message):
        # Update the text area with the extracted message
        self.text_area.append(message + "\n")

    def clearOutput(self, event):
        # Clear the text area
        self.text_area.setText("")
