package com.example.hsm;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.springframework.stereotype.Service;
import sun.security.util.DerOutputStream;
import sun.security.x509.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.InputMismatchException;

@Service
public class KeypairService {

    private static void writeToFile(byte[] data, String file) throws FileNotFoundException, IOException {
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(data);
        }
    }

    public static byte[] createCertificationRequestValue(byte[] certReqInfo, String signAlgo, byte[] signature) throws IOException, NoSuchAlgorithmException {
        final DerOutputStream der1 = new DerOutputStream();
        der1.write(certReqInfo);

        // add signature algorithm identifier, and a digital signature on the certification request information
        AlgorithmId.get(signAlgo).encode(der1);
        der1.putBitString(signature);

        // final DER encoded output
        final DerOutputStream der2 = new DerOutputStream();
        der2.write((byte) 48, der1);
        return der2.toByteArray();
    }

    public static String createPEMFormat(byte[] data) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final PrintStream ps = new PrintStream(out);
        ps.println("-----BEGIN NEW CERTIFICATE REQUEST-----");
        ps.println(java.util.Base64.getMimeEncoder().encodeToString(Base64.decode(data)));
        ps.println("-----END NEW CERTIFICATE REQUEST-----");
        return out.toString();
    }

    private static X509Certificate generateCertificate(String dn, String issuer, KeyPair pair, int days, String algorithm)
            throws GeneralSecurityException, IOException {
        PrivateKey privkey = pair.getPrivate();
        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + days * 86400000L);
        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);
        X500Name issuerName = new X500Name(issuer);
        AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        if ("1.8".equals(System.getProperty("java.specification.version"))) {
            info.set(X509CertInfo.VALIDITY, interval);
            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
            info.set(X509CertInfo.SUBJECT, owner); // Người sở hữu
            info.set(X509CertInfo.ISSUER, issuerName); // Cơ quan phát hành
            info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
        } else if ("1.7".equals(System.getProperty("java.specification.version"))) {
            info.set(X509CertInfo.VALIDITY, interval);
            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
            info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
            info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
            info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
        }

//        System.out.println("PrivateKey: " + privkey);
        // Sign the cert to identify the algorithm that's used.
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);

        // Update the algorith, and resign.
        algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);
        return cert;
    }

    public String createKey(String name) {
        try {
//            String configFile = "/home/cmc/fullservice/utimaco/pkcs11-utimaco-slot3.cfg";

            String configFileString = "name = Utimaco\n" +
                    "library = /opt/utimaco/PKCS11_R2/lib/libcs_pkcs11_R2.so\n" +
                    "description = Utimaco HSM config\n" +
                    "slot = 3";
            byte[] pkcs11ConfigBytes = configFileString.getBytes();
            ByteArrayInputStream configFile = new ByteArrayInputStream(pkcs11ConfigBytes);
            Provider HSMProvider = new sun.security.pkcs11.SunPKCS11(configFile);
            Security.addProvider(HSMProvider);

            // Print the Java crypto provider properties
            System.out.println("Provider HSMProvider properties:");
            System.out.println("Provider name: " + HSMProvider.getName());
            System.out.println("Provider version: " + String.valueOf(HSMProvider.getVersion()));
            System.out.println("Provider info: " + HSMProvider.getInfo());
            System.out.println("Provider className: " + HSMProvider.getClass().getName());

            //Get the key store.
            KeyStore keyStore = KeyStore.getInstance("PKCS11", HSMProvider);

            System.out.println("KeyStore keyStore properties:");
            System.out.println("KeyStore keyStore DefaultType: " + keyStore.getDefaultType());
            System.out.println("KeyStore keyStore Type: " + keyStore.getType());

            //Load the key store.
            String userPin = "1234"; // The pin to unlock the HSM
            keyStore.load(null, userPin.toCharArray());

            java.util.Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                System.out.println("------------alias------------");
                System.out.println(aliases.nextElement());
            }

            // Generate the keypair
            SecureRandom sr = new SecureRandom();
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, sr);
            KeyPair keyPair = keyGen.generateKeyPair();
            PrivateKey pk = keyPair.getPrivate();

            X509Certificate rootCertificate = generateCertificate("CN=TuanPA,OU=Viện Nghiên Cứu Ứng dụng CMC,O=CMC Corporation,L=Cầu Giấy,S=Hà nội,C=Việt Nam,STREET=Tran Hung Dao,Email=hunga1k15tv@gmail.com,UID=145773219", "CN=Nguyen Viet Hung,OU=Viện Nghiên Cứu Ứng dụng CMC,O=CMC Corporation,L=Cầu Giấy,S=Hà nội,C=Việt Nam,STREET=Tran Hung Dao,Email=hunga1k15tv@gmail.com,UID=145773219", keyPair, 3, "SHA256WithRSA");

            // Create Chain
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = rootCertificate;
//            System.out.println(Arrays.toString(chain));
            keyStore.setKeyEntry(name, pk, userPin.toCharArray(), chain);
//
//            String filePathToStore = "./test.p12";
//            String password = "1234";
//            OutputStream writeStream = new FileOutputStream(filePathToStore);
//            keyStore.store(writeStream, password.toCharArray());
            keyStore.store(null);
            System.out.println("------------------------------------------------------------");
            aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                System.out.println("------------alias------------");
                System.out.println(aliases.nextElement());
            }
            return "Success";
        } catch (Throwable thr) {
            return "fault";
        }
    }

    public String createCer(String alias) {
        try {
            String configFileString = "name = Utimaco\n" +
                    "library = /opt/utimaco/PKCS11_R2/lib/libcs_pkcs11_R2.so\n" +
                    "description = Utimaco HSM config\n" +
                    "slot = 3";
            byte[] pkcs11ConfigBytes = configFileString.getBytes();
            ByteArrayInputStream configFile = new ByteArrayInputStream(pkcs11ConfigBytes);

            Provider HSMProvider = new sun.security.pkcs11.SunPKCS11(configFile);
            Security.addProvider(HSMProvider);

            System.out.println("HSMProvider is not null, create keystore");
            KeyStore HSMKeyStore = KeyStore.getInstance("PKCS11", HSMProvider);

            System.out.println("KeyStore keyStore properties:");
            System.out.println("KeyStore keyStore DefaultType: " + KeyStore.getDefaultType());
            System.out.println("KeyStore keyStore Type: " + HSMKeyStore.getType());

            //Load the key store.
            String userPin = "1234"; // The pin to unlock the HSM
            HSMKeyStore.load(null, userPin.toCharArray());
            java.util.Enumeration<String> aliases = HSMKeyStore.aliases();
            System.out.println(System.getenv("JAVA_HOME"));

            if (HSMKeyStore.containsAlias(alias)) {
                System.out.println(alias);
                java.security.cert.Certificate certificate = HSMKeyStore.getCertificate(alias);
                PublicKey publicKey = certificate.getPublicKey();
                PrivateKey privateKey = (PrivateKey) HSMKeyStore.getKey(alias, userPin.toCharArray());
                // Signature rsa = Signature.getInstance("SHA256withRSA");
                String algo = privateKey.getAlgorithm();
                System.out.println("Algo PrivateKey: " + algo);
                System.out.println("PrivateKey: " + privateKey);
                X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
                x500NameBld.addRDN(BCStyle.CN, "PAT");
                x500NameBld.addRDN(BCStyle.C, "Viet Nam");
                x500NameBld.addRDN(BCStyle.ST, "Hà nội");
                x500NameBld.addRDN(BCStyle.L, "Cầu Giấy");
                x500NameBld.addRDN(BCStyle.O, "CMC Corporation");
                x500NameBld.addRDN(BCStyle.OU, "Viện Nghiên Cứu Ứng dụng CMC");
                x500NameBld.addRDN(BCStyle.UID, "1457732196");
                x500NameBld.addRDN(BCStyle.UID, "1457732189");
                x500NameBld.addRDN(BCStyle.TELEPHONE_NUMBER, "0339069405");
                x500NameBld.addRDN(BCStyle.EmailAddress, "tuanpa.tpa@gmail.com");
                x500NameBld.addRDN(BCStyle.STREET, "số 15");
                org.bouncycastle.asn1.x500.X500Name subject = x500NameBld.build();

                PKCS10CertificationRequestBuilder p10Builder =
                        new JcaPKCS10CertificationRequestBuilder(
                                subject, publicKey);

                JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
                ContentSigner signer = csBuilder.setProvider(HSMProvider).build(privateKey);
                PKCS10CertificationRequest csr = p10Builder.build(signer);
                PemObject pemObject = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
                StringWriter strWriter;
                try (JcaPEMWriter pemWriter = new JcaPEMWriter(strWriter = new StringWriter())) {
                    pemWriter.writeObject(pemObject);
                }
//                writeToFile(strWriter.toString().getBytes(), "tuan.csr");
                System.out.println(strWriter.toString());
            } else {
                throw new InputMismatchException("Khong co alias thoa man");
            }
        } catch (Throwable thr) {
            return "fault";
        }
        return "success";
    }
}
