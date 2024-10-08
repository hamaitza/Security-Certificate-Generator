import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import javax.security.auth.x500.X500Principal;
import java.awt.List;
import java.security.Security;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.io.*;
import java.math.BigInteger;
import java.util.*;


import javax.security.auth.x500.X500Principal;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory.*;

public class Main extends JFrame {
    private final CertificateGenerator generator;
    private final JFileChooser fileChooser;
    private File selectedFolder;
    private JButton selectFolderButton;

    public Main() {
        generator = new CertificateGenerator();
        fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        setTitle("Certificate Manager");
        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        // Background image
        JLabel background = new JLabel();
        background.setIcon(new ImageIcon(new ImageIcon("D:\\JavaProjects\\proiect\\pure-black-background-py9pa0f1mlsscm9s.png").getImage().getScaledInstance(800, 600, Image.SCALE_SMOOTH)));
        setContentPane(background);
        background.setLayout(new BorderLayout());

        // Adding cat image next to the title
        JLabel titleLabel = new JLabel("Certificate Manager", SwingConstants.CENTER);
        titleLabel.setFont(new Font("Arial", Font.BOLD, 24));
        titleLabel.setForeground(Color.WHITE);
        JLabel catLabel = new JLabel();
        JPanel titlePanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        titlePanel.setOpaque(false);
        titlePanel.add(titleLabel);
        titlePanel.add(catLabel);

        JPanel buttonPanel = new JPanel(new GridBagLayout());
        buttonPanel.setOpaque(false); // Make the panel transparent
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 0;
        gbc.gridy = 0;

        selectFolderButton = new JButton("Select Folder");
        selectFolderButton.setPreferredSize(new Dimension(400, 50)); // Set button size
        selectFolderButton.setFont(new Font("Arial", Font.PLAIN, 18)); // Set font size
        selectFolderButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectFolder();
            }
        });
        buttonPanel.add(selectFolderButton, gbc);

        gbc.gridy++;
        JButton generateButton = new JButton("Generate Certificate Hierarchy");
        generateButton.setPreferredSize(new Dimension(400, 50));
        generateButton.setFont(new Font("Arial", Font.PLAIN, 18));
        generateButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                generateCertificates();
            }
        });
        buttonPanel.add(generateButton, gbc);

        gbc.gridy++;
        JButton revokeButton = new JButton("Revoke Certificate");
        revokeButton.setPreferredSize(new Dimension(400, 50));
        revokeButton.setFont(new Font("Arial", Font.PLAIN, 18));
        revokeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                revokeCertificate();
            }
        });
        buttonPanel.add(revokeButton, gbc);

        gbc.gridy++;
        JButton extendButton = new JButton("Extend Certificate");
        extendButton.setPreferredSize(new Dimension(400, 50));
        extendButton.setFont(new Font("Arial", Font.PLAIN, 18));
        extendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                extendCertificate();
            }
        });
        buttonPanel.add(extendButton, gbc);

        gbc.gridy++;
        JButton validateButton = new JButton("Validate Certificate Chain");
        validateButton.setPreferredSize(new Dimension(400, 50));
        validateButton.setFont(new Font("Arial", Font.PLAIN, 18));
        validateButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                validateCertificate();
            }
        });
        buttonPanel.add(validateButton, gbc);

        background.add(titlePanel, BorderLayout.NORTH);
        background.add(buttonPanel, BorderLayout.SOUTH);
    }

    private void selectFolder() {
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            selectedFolder = fileChooser.getSelectedFile();
            selectFolderButton.setText(selectedFolder.getAbsolutePath());
        }
    }

    private void generateCertificates() {
        if (selectedFolder == null) {
            JOptionPane.showMessageDialog(this, "Please select a folder first.");
            return;
        }

        try {
            String folderName = UUID.randomUUID().toString();
            File certificateFolder = new File(selectedFolder, folderName);
            if (!certificateFolder.mkdirs()) {
                throw new IOException("Failed to create directory for certificates.");
            }

            KeyPair rootKeyPair = generator.generateKeyPair();
            X509Certificate rootCertificate = generator.generateRootCertificate(rootKeyPair);
            saveCertificate(rootCertificate, certificateFolder.getAbsolutePath() + "/rootCertificate.pem");
            savePrivateKey(rootKeyPair.getPrivate(), certificateFolder.getAbsolutePath() + "/rootPrivateKey.pem");

            // Cheia privată a certificatului rădăcină este necesară pentru a semna certificatul intermediar
            KeyPair intermediateKeyPair = generator.generateKeyPair();
            X509Certificate intermediateCertificate = generator.generateIntermediateCertificate(rootCertificate, rootKeyPair.getPrivate(), intermediateKeyPair);
            saveCertificate(intermediateCertificate, certificateFolder.getAbsolutePath() + "/intermediateCertificate.pem");
            savePrivateKey(intermediateKeyPair.getPrivate(), certificateFolder.getAbsolutePath() + "/intermediatePrivateKey.pem");

            // Cheia privată a certificatului intermediar este necesară pentru a semna certificatul de utilizator final
            KeyPair endUserKeyPair = generator.generateKeyPair();
            X509Certificate endUserCertificate = generator.generateEndUserCertificate(intermediateCertificate, intermediateKeyPair.getPrivate(), endUserKeyPair);
            saveCertificate(endUserCertificate, certificateFolder.getAbsolutePath() + "/endUserCertificate.pem");
            savePrivateKey(endUserKeyPair.getPrivate(), certificateFolder.getAbsolutePath() + "/endUserPrivateKey.pem");

            JOptionPane.showMessageDialog(this, "Certificates generated successfully!");
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error generating certificates: " + e.getMessage());
        }
    }

    private void revokeCertificate() {
        if (selectedFolder == null) {
            JOptionPane.showMessageDialog(this, "Please select a folder first.");
            return;
        }
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File certificateFile = fileChooser.getSelectedFile();

            // Select the private key file for the CA certificate
            returnValue = fileChooser.showOpenDialog(this);
            if (returnValue != JFileChooser.APPROVE_OPTION) {
                return;
            }
            File privateKeyFile = fileChooser.getSelectedFile();

            try {
                // Load CA certificate and private key
                X509Certificate caCertificate = loadCertificate(certificateFile);
                PrivateKey caPrivateKey = loadPrivateKey(privateKeyFile);
                BigInteger serialNumber = caCertificate.getSerialNumber();

                // Create a new CRL
                X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
                        new X500Name(caCertificate.getSubjectX500Principal().getName()),
                        new Date()
                );

                // Add the certificate to be revoked to the CRL
                crlBuilder.addCRLEntry(serialNumber, new Date(), 0);

                // Sign the CRL
                ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey);
                X509CRLHolder crlHolder = crlBuilder.build(signer);
                X509CRL crl = new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);

                // Save the CRL to a file
                File crlFile = new File(selectedFolder, "crl.pem");
                try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(crlFile))) {
                    writer.writeObject(crl);
                }

                JOptionPane.showMessageDialog(this, "Certificate revoked successfully!");
            } catch (Exception e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(this, "Error revoking certificate: " + e.getMessage());
            }
        }
    }


    private void extendCertificate() {
        if (selectedFolder == null) {
            JOptionPane.showMessageDialog(this, "Please select a folder first.");
            return;
        }

        // Select the certificate file
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File certificateFile = fileChooser.getSelectedFile();
        if (!certificateFile.exists()) {
            JOptionPane.showMessageDialog(this, "Certificate file not found.");
            return;
        }

        // Select the private key file
        returnValue = fileChooser.showOpenDialog(this);
        if (returnValue != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File privateKeyFile = fileChooser.getSelectedFile();
        if (!privateKeyFile.exists()) {
            JOptionPane.showMessageDialog(this, "Private key file not found.");
            return;
        }

        try {
            X509Certificate oldCertificate = loadCertificate(certificateFile);
            PrivateKey privateKey = loadPrivateKey(privateKeyFile);



            // Extend the certificate validity by adding one year to the current end date
            X500Name issuer = new X500Name(oldCertificate.getIssuerX500Principal().getName());
            BigInteger serial = oldCertificate.getSerialNumber();
            Date startDate = oldCertificate.getNotBefore();
            Date currentEndDate = oldCertificate.getNotAfter();

            // Add one year to the current end date
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(currentEndDate);
            calendar.add(Calendar.YEAR, 1);
            Date newEndDate = calendar.getTime();

            X500Name subject = new X500Name(oldCertificate.getSubjectX500Principal().getName());

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer, serial, startDate, newEndDate, subject, oldCertificate.getPublicKey());

            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            X509Certificate newCertificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

            // Save the new certificate, replacing the old one
            saveCertificate(newCertificate, certificateFile.getAbsolutePath());

            // Display the extended certificate
            System.out.println("Extended Certificate:");
            System.out.println(newCertificate);

            JOptionPane.showMessageDialog(this, "Certificate extended successfully!");
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error extending certificate: " + e.getMessage());
        }
    }

    private void validateCertificate() {
        try {
            // Select the root certificate file
            File rootCertFile = selectFile("Select Root Certificate File");
            if (rootCertFile == null || !rootCertFile.exists()) {
                JOptionPane.showMessageDialog(this, "Root certificate file not found.");
                return;
            }

            // Select the certificate file to validate
            File certFileToValidate = selectFile("Select Certificate File to Validate");
            if (certFileToValidate == null || !certFileToValidate.exists()) {
                JOptionPane.showMessageDialog(this, "Certificate file to validate not found.");
                return;
            }

            // Select the CRL file
            File crlFile = selectFile("Select Certificate Revocation List (CRL) File");
            if (crlFile == null || !crlFile.exists()) {
                JOptionPane.showMessageDialog(this, "CRL file not found.");
                return;
            }

            // Load the root certificate
            X509Certificate rootCertificate = loadCertificate(rootCertFile);

            // Check if the root certificate is valid
            if (!isCertificateValid(rootCertificate)) {
                JOptionPane.showMessageDialog(this, "Root certificate is not valid.");
                return;
            }

            // Load the certificate to validate
            X509Certificate certificateToValidate = loadCertificate(certFileToValidate);

            // Load the CRL
            X509CRL crl = loadCRL(crlFile);

            // Perform certificate validation
            boolean isValid = validateCertificate(rootCertificate, certificateToValidate, crl);

            // Display validation result
            if (isValid) {
                JOptionPane.showMessageDialog(this, "Certificate is valid.");
            } else {
                JOptionPane.showMessageDialog(this, "Certificate is not valid.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error validating certificate: " + e.getMessage());
        }
    }

    private boolean isCertificateValid(X509Certificate certificate) throws CertificateException {
        try {
            certificate.checkValidity();
            return true;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            return false;
        }
    }

    private boolean validateCertificate(X509Certificate rootCertificate, X509Certificate certificateToValidate, X509CRL crl) throws Exception {
        try {
            // Verify the certificate chain
            certificateToValidate.verify(rootCertificate.getPublicKey());

            // Check if the certificate is revoked
            if (crl.isRevoked(certificateToValidate)) {
                return false;
            }

            if (crl.isRevoked(rootCertificate)) {
                return false;
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private File selectFile(String dialogTitle) {
        fileChooser.setDialogTitle(dialogTitle);
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            return fileChooser.getSelectedFile();
        }
        return null;
    }

    private boolean verifyPrivateKeyMatch(X509Certificate certificate, PrivateKey privateKey) throws Exception {
        // Creăm un mesaj pentru a fi semnat
        byte[] message = "Test message".getBytes();

        // Semnăm mesajul folosind cheia privată
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message);
        byte[] signatureBytes = signature.sign();

        // Verificăm semnătura folosind certificatul asociat cheii private
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(certificate.getPublicKey());
        verifier.update(message);

        return verifier.verify(signatureBytes);
    }


    private PrivateKey loadPrivateKey(File pemFile) throws IOException {
        try (FileReader keyReader = new FileReader(pemFile);
             PEMParser pemParser = new PEMParser(keyReader)) {
            Object object = pemParser.readObject();
            PEMKeyPair pemKeyPair = (PEMKeyPair) object;
            return new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        }
    }

    private X509CRL loadCRL(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file);
             BufferedInputStream bis = new BufferedInputStream(fis)) {
            Security.addProvider(new BouncyCastleProvider());
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
            X509CRL crl = (X509CRL) certFactory.generateCRL(bis);
            return crl;
        }
    }

    private X509Certificate loadCertificate(File file) throws Exception {
        try (FileReader fileReader = new FileReader(file);
             PEMParser pemParser = new PEMParser(fileReader)) {
            Object object = pemParser.readObject();
            if (object instanceof X509CertificateHolder) {
                return new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder) object);
            } else {
                throw new IllegalArgumentException("Invalid certificate file");
            }
        }
    }

    private void saveCertificate(X509Certificate certificate, String filePath) throws Exception {
        try (OutputStream out = new FileOutputStream(filePath);
             JcaPEMWriter writer = new JcaPEMWriter(new java.io.OutputStreamWriter(out))) {
            writer.writeObject(certificate);
        }
    }

    private void savePrivateKey(PrivateKey privateKey, String filePath) throws Exception {
        try (OutputStream out = new FileOutputStream(filePath);
             JcaPEMWriter writer = new JcaPEMWriter(new java.io.OutputStreamWriter(out))) {
            writer.writeObject(privateKey);
        }
    }



    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                Main mainFrame = new Main();
                mainFrame.setVisible(true);
            }
        });
    }
}