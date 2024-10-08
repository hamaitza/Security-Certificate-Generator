import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static X509Certificate generateRootCertificate(KeyPair keyPair) throws Exception {
        X500Name issuer = new X500Name("CN=Root CA");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date startDate = new Date(System.currentTimeMillis() - 10000);
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);
        X500Name subject = issuer;

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, startDate, endDate, subject, keyPair.getPublic());
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    public static X509Certificate generateIntermediateCertificate(X509Certificate rootCertificate, PrivateKey rootPrivateKey, KeyPair intermediateKeyPair) throws Exception {
        X500Name issuer = new X500Name(rootCertificate.getSubjectX500Principal().getName());
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis() + 1);
        Date startDate = new Date(System.currentTimeMillis() - 10000);
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);
        X500Name subject = new X500Name("CN=Intermediate CA");

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, startDate, endDate, subject, intermediateKeyPair.getPublic());
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(rootPrivateKey);
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    public static X509Certificate generateEndUserCertificate(X509Certificate intermediateCertificate, PrivateKey intermediatePrivateKey, KeyPair endUserKeyPair) throws Exception {
        X500Name issuer = new X500Name(intermediateCertificate.getSubjectX500Principal().getName());
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis() + 2);
        Date startDate = new Date(System.currentTimeMillis() - 10000);
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);
        X500Name subject = new X500Name("CN=End User");

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, startDate, endDate, subject, endUserKeyPair.getPublic());
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(intermediatePrivateKey);
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }
}
