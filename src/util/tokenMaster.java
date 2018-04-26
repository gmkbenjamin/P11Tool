package util;

import java.awt.Color;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.event.ActionListener;
import java.io.IOException;
import java.awt.event.ActionEvent;
import javax.swing.JTextPane;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;


import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_INFO;
import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import javax.swing.JTable;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JProgressBar;
import javax.swing.JPopupMenu;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.JMenuItem;

public class tokenMaster {

    private JFrame frame;
    private JTextField textField;
    private JTextField textField_1;
    private JLabel lblSlotNumber;
    private JLabel lblTokenPassword;
    private JPasswordField passwordField;
    private JButton button;
    private JLabel lblOutput;
    private JLabel lblContents;
    private String lib;
    private JFileChooser chooser;
    private JTextPane output = new JTextPane();
    private StyledDocument doc = output.getStyledDocument();
    private JScrollPane scrollPane_1;
    private JTable table;
    private String passwd;
    private JProgressBar progressBar;
    private JPopupMenu popupMenu;
    private JMenuItem mntmCopy;
    private JMenuItem mntmPaste;
    private JMenuItem mntmSelectAll;

    /**
     * Launch the application.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    tokenMaster window = new tokenMaster();
                    window.frame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    /**
     * Create the application.
     */
    public tokenMaster() {
        initialize();
    }

    /**
     * Initialize the contents of the frame.
     */
    private void initialize() {
        frame = new JFrame();
        frame.setBounds(100, 100, 828, 517);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        textField = new JTextField();
        textField.setColumns(10);
        SimpleAttributeSet error = new SimpleAttributeSet();
        StyleConstants.setForeground(error, Color.RED);
        JButton btnBrowse = new JButton("Browse");
        btnBrowse.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (e.getSource() == btnBrowse) {
                    chooser = new JFileChooser();
                    chooser.setCurrentDirectory(new java.io.File("."));
                    chooser.setDialogTitle("choosertitle");
                    chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                    chooser.setAcceptAllFileFilterUsed(true);
                    if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                        textField.setText(chooser.getSelectedFile().getAbsolutePath());

                    }
                }
            }
        });

        JButton btnLoadLibrary = new JButton("Load library");
        btnLoadLibrary.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                progressBar.setValue(0);
                progressBar.setStringPainted(true);
                output.setText("");
                lib = textField.getText();
                CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
                try {
                    doc.insertString(doc.getLength(), "Initializing...\n", null);
                } catch (BadLocationException e2) {
                    // TODO Auto-generated catch block
                    e2.printStackTrace();
                }

                try {
                    PKCS11 p11 = PKCS11.getInstance(lib, "C_GetFunctionList", initArgs, false);
                    doc.insertString(doc.getLength(), "Getting instance...\n", null);
                    doc.insertString(doc.getLength(), "Getting info...\n", null);
                    CK_INFO cki = p11.C_GetInfo();
                    doc.insertString(doc.getLength(), cki + "\n", null);
                    doc.insertString(doc.getLength(), "Getting slot list...\n", null);
                    long[] slots = p11.C_GetSlotList(true);
                    doc.insertString(doc.getLength(), "Number of slots: " + slots.length + "\n", null);
                    if (slots.length > 0) {
                        for (long slot : slots) {
                            doc.insertString(doc.getLength(), "\n\n" + "Openning session on slot " + slot + "...\n", null);
                            long sessionhandle = p11.C_OpenSession(slot, PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
                            doc.insertString(doc.getLength(), "Getting session info...\n", null);
                            CK_SESSION_INFO sessionInfo = p11.C_GetSessionInfo(sessionhandle);
                            doc.insertString(doc.getLength(), sessionInfo + "\n", null);
                            doc.insertString(doc.getLength(), "Getting token info...\n", null);
                            CK_TOKEN_INFO tokenInfo = p11.C_GetTokenInfo(slot);
                            doc.insertString(doc.getLength(), tokenInfo + "...\n", null);

                        }
                    }
                } catch (IOException | PKCS11Exception e1) {
                    try {
                        doc.insertString(doc.getLength(), e1.getMessage(), error);
                    } catch (BadLocationException e2) {
                        // TODO Auto-generated catch block
                        e2.printStackTrace();
                    }
                    e1.printStackTrace();
                } catch (BadLocationException e1) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
            }
        });

        textField_1 = new JTextField();
        textField_1.setColumns(10);

        JLabel lblPkcsLibrary = new JLabel("PKCS11 Library:");

        lblSlotNumber = new JLabel("Slot Number:");

        lblTokenPassword = new JLabel("Token Password:");

        passwordField = new JPasswordField();

        button = new JButton("Login");
        button.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
            }
        });

        lblOutput = new JLabel("Output:");

        lblContents = new JLabel("Contents:");

        JScrollPane scrollPane = new JScrollPane();

        scrollPane_1 = new JScrollPane();

        progressBar = new JProgressBar();
        GroupLayout groupLayout = new GroupLayout(frame.getContentPane());
        groupLayout.setHorizontalGroup(
                groupLayout.createParallelGroup(Alignment.LEADING)
                        .addGroup(groupLayout.createSequentialGroup()
                                .addGap(14)
                                .addGroup(groupLayout.createParallelGroup(Alignment.TRAILING)
                                        .addComponent(lblContents)
                                        .addComponent(lblOutput))
                                .addPreferredGap(ComponentPlacement.UNRELATED)
                                .addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
                                        .addGroup(groupLayout.createSequentialGroup()
                                                .addComponent(progressBar, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                .addContainerGap())
                                        .addGroup(groupLayout.createSequentialGroup()
                                                .addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
                                                        .addComponent(scrollPane_1, GroupLayout.DEFAULT_SIZE, 614, Short.MAX_VALUE)
                                                        .addGroup(groupLayout.createParallelGroup(Alignment.LEADING, false)
                                                                .addGroup(groupLayout.createSequentialGroup()
                                                                        .addComponent(lblPkcsLibrary)
                                                                        .addPreferredGap(ComponentPlacement.UNRELATED)
                                                                        .addComponent(textField, GroupLayout.PREFERRED_SIZE, 335, GroupLayout.PREFERRED_SIZE)
                                                                        .addGap(18)
                                                                        .addComponent(btnBrowse)
                                                                        .addGap(18)
                                                                        .addComponent(btnLoadLibrary))
                                                                .addComponent(scrollPane, GroupLayout.DEFAULT_SIZE, 614, Short.MAX_VALUE)
                                                                .addGroup(groupLayout.createSequentialGroup()
                                                                        .addComponent(lblSlotNumber)
                                                                        .addPreferredGap(ComponentPlacement.UNRELATED)
                                                                        .addComponent(textField_1, GroupLayout.PREFERRED_SIZE, 24, GroupLayout.PREFERRED_SIZE)
                                                                        .addGap(57)
                                                                        .addComponent(lblTokenPassword)
                                                                        .addGap(18)
                                                                        .addComponent(passwordField, GroupLayout.PREFERRED_SIZE, 104, GroupLayout.PREFERRED_SIZE)
                                                                        .addGap(28)
                                                                        .addComponent(button))))
                                                .addContainerGap(126, Short.MAX_VALUE))))
        );
        groupLayout.setVerticalGroup(
                groupLayout.createParallelGroup(Alignment.LEADING)
                        .addGroup(groupLayout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
                                        .addComponent(textField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(btnBrowse)
                                        .addComponent(btnLoadLibrary)
                                        .addComponent(lblPkcsLibrary))
                                .addGap(8)
                                .addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
                                        .addComponent(textField_1, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(lblSlotNumber)
                                        .addComponent(lblTokenPassword)
                                        .addComponent(passwordField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(button))
                                .addGap(10)
                                .addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
                                        .addComponent(lblContents)
                                        .addComponent(scrollPane_1, GroupLayout.PREFERRED_SIZE, 169, GroupLayout.PREFERRED_SIZE))
                                .addGap(18)
                                .addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
                                        .addComponent(lblOutput)
                                        .addComponent(scrollPane, GroupLayout.PREFERRED_SIZE, 165, GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(ComponentPlacement.UNRELATED)
                                .addComponent(progressBar, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addGap(7))
        );

        popupMenu = new JPopupMenu();
        addPopup(textField, popupMenu);

        mntmCopy = new JMenuItem("Copy");
        popupMenu.add(mntmCopy);

        mntmPaste = new JMenuItem("Paste");
        popupMenu.add(mntmPaste);

        mntmSelectAll = new JMenuItem("Select All");
        popupMenu.add(mntmSelectAll);

        table = new JTable();
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        scrollPane_1.setViewportView(table);


        scrollPane.setViewportView(output);
        frame.getContentPane().setLayout(groupLayout);
    }

    public static void logout(PKCS11 p11, long sessionhandle, String passwd) throws PKCS11Exception {
        System.out.println("Logging out...");
        if (passwd != null)
            p11.C_Logout(sessionhandle);
        System.out.println();

        System.out.println("Closing session...");
        p11.C_CloseSession(sessionhandle);
        System.out.println();

    }

    private static void addPopup(Component component, final JPopupMenu popup) {
        component.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showMenu(e);
                }
            }

            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showMenu(e);
                }
            }

            private void showMenu(MouseEvent e) {
                popup.show(e.getComponent(), e.getX(), e.getY());
            }
        });
    }
}
