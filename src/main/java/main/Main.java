package main;

import auth_2_0.Auth;
import ekyc.response.Resp;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import java.io.IOException;
import java.io.StringReader;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;


public class Main {

    public static void main(String[] args) throws IOException {
        OTPAuth OTPAuth = new OTPAuth();
        EKYCService ekycService = new EKYCService();
        try {
            HelperClass helperClass = new HelperClass(OTPAuth.configProp);
            OTPAuth.readProperties(helperClass);

            String uid = args[0];
            String txn = "UKC:"+args[1];
            String optRequest = args[2];
            System.out.println("UID: "+uid+" TxnId: "+txn+" OTP :"+optRequest);
            Auth auth = OTPAuth.createResidentAuth(uid, txn, optRequest, new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").format(new Date()), "");
            String signedXml = helperClass.getSignedXml(auth);
            String rad = Base64.getEncoder().encodeToString(signedXml.getBytes());
            String ekycResponse = ekycService.getEkycResponse(uid, rad);

            JAXBContext jaxbContext = JAXBContext.newInstance(Resp.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            Resp resp = (Resp) unmarshaller.unmarshal(new StringReader(ekycResponse));
            System.out.println(" KYC Response with status : " + resp.getRet());
            if(resp.getRet().equalsIgnoreCase("N")){
                System.out.println("Error code: " + resp.getErr());
                System.out.println("***************************************");

                System.out.println(ekycResponse);

            }else {
                byte[] encryptedString = Base64.getDecoder().decode(resp.getKycRes());

                DataDecryptor dataDecryptor = new DataDecryptor();
                byte[] decryptedKycResp = dataDecryptor.decrypt(encryptedString);
                System.out.println("************* Decrypted ekyc response ***********");

                System.out.println(new String(decryptedKycResp));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }



}
