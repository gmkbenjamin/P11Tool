package p11tool.gui;

import p11tool.crypto.Pkcs11Support;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_INFO;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.IOException;

/**
 * Minimal Swing front-end for loading a PKCS#11 library and listing token objects.
 * Full GUI feature parity with the CLI is deferred; this covers browse / load / login / list.
 */
public final class TokenMaster {

    private PKCS11 p11;
    private long[] slots = new long[0];
    private long session;

    private final JTextField libraryField = new JTextField(40);
    private final JTextField slotField = new JTextField("0", 4);
    private final JPasswordField pinField = new JPasswordField(12);
    private final JTextArea output = new JTextArea();

    private TokenMaster() {
    }

    public static void launch() {
        SwingUtilities.invokeLater(() -> new TokenMaster().show());
    }

    private void show() {
        JFrame frame = new JFrame("P11Tool — Token Master");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setSize(860, 560);

        JButton browse = new JButton("Browse");
        browse.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser(".");
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            if (chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                libraryField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });

        JButton load = new JButton("Load library");
        load.addActionListener(e -> loadLibrary());

        JButton login = new JButton("Login & list");
        login.addActionListener(e -> loginAndList());

        var top = new javax.swing.JPanel(new GridBagLayout());
        top.setBorder(new EmptyBorder(10, 10, 10, 10));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;

        c.gridx = 0; c.gridy = 0;
        top.add(new JLabel("PKCS#11 library:"), c);
        c.gridx = 1; c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL;
        top.add(libraryField, c);
        c.gridx = 2; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        top.add(browse, c);
        c.gridx = 3;
        top.add(load, c);

        c.gridx = 0; c.gridy = 1;
        top.add(new JLabel("Slot index:"), c);
        c.gridx = 1; c.fill = GridBagConstraints.NONE;
        top.add(slotField, c);
        c.gridx = 2;
        top.add(new JLabel("PIN:"), c);
        c.gridx = 3; c.fill = GridBagConstraints.HORIZONTAL;
        top.add(pinField, c);

        c.gridx = 4; c.gridy = 1; c.fill = GridBagConstraints.NONE;
        top.add(login, c);

        output.setEditable(false);
        output.setLineWrap(true);

        frame.setLayout(new BorderLayout());
        frame.add(top, BorderLayout.NORTH);
        frame.add(new JScrollPane(output), BorderLayout.CENTER);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private void append(String text) {
        output.append(text);
        output.setCaretPosition(output.getDocument().getLength());
    }

    private void loadLibrary() {
        output.setText("");
        String lib = libraryField.getText().trim();
        if (lib.isEmpty()) {
            JOptionPane.showMessageDialog(null, "Select a PKCS#11 library first.");
            return;
        }
        new SwingWorker<Void, String>() {
            @Override
            protected Void doInBackground() {
                try {
                    closeSession();
                    publish("Initializing " + lib + "\n");
                    p11 = Pkcs11Support.loadModule(lib);
                    CK_INFO info = p11.C_GetInfo();
                    publish(info + "\n");
                    slots = p11.C_GetSlotList(true);
                    publish("Slots with tokens: " + slots.length + "\n");
                    for (int i = 0; i < slots.length; i++) {
                        CK_TOKEN_INFO tokenInfo = p11.C_GetTokenInfo(slots[i]);
                        publish("[" + i + "] slotId=" + slots[i] + " " + new String(tokenInfo.label).trim() + "\n");
                    }
                } catch (IOException | PKCS11Exception ex) {
                    publish("ERROR: " + ex.getMessage() + "\n");
                }
                return null;
            }

            @Override
            protected void process(java.util.List<String> chunks) {
                chunks.forEach(TokenMaster.this::append);
            }
        }.execute();
    }

    private void loginAndList() {
        if (p11 == null) {
            JOptionPane.showMessageDialog(null, "Load a library first.");
            return;
        }
        new SwingWorker<Void, String>() {
            @Override
            protected Void doInBackground() {
                try {
                    closeSession();
                    int index = Integer.parseInt(slotField.getText().trim());
                    if (index < 0 || index >= slots.length) {
                        publish("Invalid slot index\n");
                        return null;
                    }
                    session = Pkcs11Support.openRwSession(p11, slots[index]);
                    String pin = new String(pinField.getPassword());
                    Pkcs11Support.loginIfNeeded(p11, session, pin);
                    publish("Logged in on slot index " + index + "\n");
                    p11.C_FindObjectsInit(session, new CK_ATTRIBUTE[0]);
                    long[] handles = p11.C_FindObjects(session, Pkcs11Support.MAX_OBJECTS);
                    p11.C_FindObjectsFinal(session);
                    publish(handles.length + " object(s):\n");
                    for (long handle : handles) {
                        CK_ATTRIBUTE[] attrs = {
                                new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL),
                                new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS)
                        };
                        p11.C_GetAttributeValue(session, handle, attrs);
                        publish("  handle=" + handle + " " + attrs[0] + " " + attrs[1] + "\n");
                    }
                } catch (Exception ex) {
                    publish("ERROR: " + ex.getMessage() + "\n");
                }
                return null;
            }

            @Override
            protected void process(java.util.List<String> chunks) {
                chunks.forEach(TokenMaster.this::append);
            }
        }.execute();
    }

    private void closeSession() {
        if (p11 != null && session != 0L) {
            Pkcs11Support.closeQuietly(p11, session);
            session = 0L;
        }
    }
}
