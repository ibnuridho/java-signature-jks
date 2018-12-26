import java.io.*;
import java.security.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.lang.Object;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;

public class signature 
{
    public static void main(String[] args) 
    {
        
        signature client = new signature();
        
        try {
            //.jks file
            String jksFile = args[0];
            //JKS password
            String jksPassword = args[1];
	    //JKS alias	
            String jksAlias = args[2];
            //path/of/file.ext/
            String xmlFile = args[3];
            char[] storePass = jksPassword.toCharArray();

            File xmlf = new File(xmlFile);

            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(xmlf);

            DOMSource xmldom = new DOMSource(doc);
            
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            StreamResult stream = new StreamResult(baos);

            TransformerFactory tfactory = TransformerFactory.newInstance();
            Transformer transf = tfactory.newTransformer();
            transf.transform(xmldom, stream);
            
            byte[] dataInBytes = baos.toByteArray();
            // System.out.println(Arrays.toString(dataInBytes));
            
            FileInputStream fisjks = new FileInputStream(jksFile);
            KeyStore keystore = KeyStore.getInstance("JKS");
            // System.out.println(keystore);
            keystore.load(fisjks, storePass);
            KeyStore.ProtectionParameter keyPass = new KeyStore.PasswordProtection(storePass);
            KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(jksAlias, keyPass);
            PrivateKey privateKey = privKeyEntry.getPrivateKey();
            // System.out.println(privateKey);
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);
            signature.update(dataInBytes);

            byte[] signedInfo = signature.sign();
            // System.out.println(signature);
            String sign = Arrays.toString(signedInfo);
            // String sign = signedInfo.toString();

            System.out.println(sign);
            
        } catch (Exception e) {
            System.err.println(e.toString() + "Caught exception ");
        }
    }
}
