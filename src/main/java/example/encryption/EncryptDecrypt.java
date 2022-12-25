/*
 * Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with
 * the License. A copy of the License is located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 * Version PD
 */


package example.encryption;
//import aws.example.kms;

import static example.Utils.MAPPER;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.HashMap;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.Arrays;
import java.util.Calendar; //add by bob
import java.io.File; //add by bob for fixed content encryption;
import com.fasterxml.jackson.databind.ObjectMapper; //add by bob for fixed content encryption;
import java.nio.charset.Charset;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import com.amazonaws.auth.ClasspathPropertiesFileCredentialsProvider;

import org.apache.log4j.Logger;

//import com.amazonaws.services.rds.AmazonRDSClient; // for DB sdk
// add for database access begin.
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
//import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import com.amazonaws.services.rdsdata.AWSRDSData;
import com.amazonaws.services.rdsdata.AWSRDSDataClientBuilder;
import com.amazonaws.services.rdsdata.model.ExecuteSqlRequest;
import com.amazonaws.services.rdsdata.model.ExecuteSqlResult;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

// add for database access end.

import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.kms.KmsMasterKey;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager; // add for cacheing SDK usage 
import com.amazonaws.encryptionsdk.caching.CryptoMaterialsCache; // add for cacheing SDK usage
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache; // add for caching SDK usage
import com.amazonaws.encryptionsdk.CryptoMaterialsManager; // add for caching SDK usage
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * This class centralizes the logic for encryption and decryption of messages, to allow for easier modification.
 *
 * The guice wiring will ensure that this is a singleton; any fields initialized in the constructor will be retained
 * for subsequent invocations and/or messages.
 */
@Singleton
public class EncryptDecrypt {
    private static final Logger LOGGER = Logger.getLogger(EncryptDecrypt.class);
    private static final String K_MESSAGE_TYPE = "message type";
    private static final String TYPE_ORDER_INQUIRY = "order inquiry";
    private static final String K_ORDER_ID = "order ID";
    private static final String KEYID = "arn:aws:kms:us-east-2:484626021127:key/1f154dd3-1d7c-4ee0-aa29-01cf206e1a99";
    
    private static ByteBuffer cypherDataKey_A;
    private static ByteBuffer cypherDataKey_P;
    private static ByteBuffer plainDataKey;
    private static String cypherDataKeyStr;
    private static String cypherText_;
    private static String cypherText1_;
    private static String cypherText2_;

    private final AWSKMS kms;
    //private final KmsMasterKey masterKey;
    private final KmsMasterKey masterKeyEast;
    private final KmsMasterKey masterKeyWest;
    private MasterKeyProvider<?> provider;
    private String CMKKeyID;
    
//     // for DBAPI access by bob 20191126
//     private final static String DATABASE_ARN = "arn:aws:rds:us-east-2:484626021127:cluster:dbcluster3";

//     private final static String SECRET_STORE_ARN = "arn:aws:secretsmanager:us-east-2:484626021127:secret:dr/stg/admin-KsLQpV"; 

//     private final static String ENDPOINT = "https://dbcluster3.cluster-c43dtmdrprrh.us-east-2.rds.amazonaws.com";
// //    private final static String ENDPOINT = "dbcluster3.cluster-c43dtmdrprrh.us-east-2.rds.amazonaws.com";

//     private final static String REGION = "us-east-2";

//     private AWSRDSData awsRDSDataAPI;

    private Connection db_con;
// 	String driver = "com.mysql.cj.jdbc.Driver";
	private String driver = "com.mysql.cj.jdbc.Driver";
	//URL指向要访问的数据库名mydata
// 	private String url = "jdbc:mysql://dbcluster3.cluster-c43dtmdrprrh.us-east-2.rds.amazonaws.com:3306/activationDB";
	private String url = "jdbc:mysql://dbcluster3.cluster-c43dtmdrprrh.us-east-2.rds.amazonaws.com:3306";
	//MySQL配置时的用户名
	private String db_username = "admin";
	//MySQL配置时的密码
	private String db_password = "PWadm1n000";
	
	final AwsCrypto encryptionSdk;
    
    @SuppressWarnings("unused") // all fields are used via JSON deserialization
    private static class FormData {
        public String name;
        public String email;
        public String orderid;
        public String issue;
    }

    @Inject
    public EncryptDecrypt(@Named("keyIdEast") final String keyIdEast, @Named("keyIdWest") final String keyIdWest) {
        kms = AWSKMSClient.builder().build();
        this.masterKeyEast = new KmsMasterKeyProvider(keyIdEast).getMasterKey(keyIdEast);
        this.masterKeyWest = new KmsMasterKeyProvider(keyIdWest).getMasterKey(keyIdWest);
        this.provider = getKeyProvider(masterKeyEast, masterKeyWest);
        this.CMKKeyID = keyIdEast;
        encryptionSdk = new AwsCrypto();

        
        try {
			//加载驱动程序
			Class.forName(driver);
			//1.getConnection()方法，连接MySQL数据库！！
			LOGGER.info("Initial: try to connect to the Database! usl:" + url +"usr:" + db_username +"pass:");
			db_con = DriverManager.getConnection(url,db_username,db_password);
			if(!db_con.isClosed()) {
				LOGGER.info("Initial: Succeeded connecting to the Database!");
			} else {
			    LOGGER.info("Initial: Failed to connect to the Database!");
			}
			//要执行的SQL语句
			String sql = "select * from activationDB.DEK";
			
			boolean keyIsThere = IsEmpty(sql);
			if (!keyIsThere) {		// key is not in database, need to generate a new one;
                // generate a DEK;
                // generate data key, with CMK, with AES_128
                GenerateDataKeyRequest dataKeyRequest = new GenerateDataKeyRequest();
                //dataKeyRequest.setKeyId(KEYID);
                dataKeyRequest.setKeyId(this.CMKKeyID);
                dataKeyRequest.setKeySpec("AES_128");
                GenerateDataKeyResult dataKeyResult = kms.generateDataKey(dataKeyRequest);            
                // plain text data key
                ByteBuffer plainTextKey = dataKeyResult.getPlaintext();
                String tmp = new String(plainTextKey.array());
                LOGGER.info("Initial:GenerateDataKey the plantextKey " + tmp);
                // 使用multiple provider 加密管理 datakey，以便跨区域使用，102 begin    
                CryptoResult<byte[], ?> result = new AwsCrypto().encryptData(this.provider, plainTextKey.array());
                LOGGER.info("Initial:Got the cypherDataKeyStr by Provider:" + new String(result.getResult()) );
                this.cypherDataKey_P = ByteBuffer.wrap(result.getResult());  
                LOGGER.info("Initial:Got the cypherDataKeyStr by Provider:" + new String(this.cypherDataKey_P.array()) ); 
                // store the ciphered DEK into DB
                //String cipherDEK = new String(result.getResult());
                String base64DEK = Base64.getEncoder().encodeToString(result.getResult());
                LOGGER.info("base64DEK code length is:" + base64DEK.length());
                String insertSQL = new String("INSERT INTO activationDB.DEK(dekcode) VALUES('"+ base64DEK +"');");
                LOGGER.info("The insert SQL is :" + insertSQL);
                insterDB(insertSQL); // insert the DEK with base64 coded into database;
			} else {
    			if(!db_con.isClosed()) {
    				LOGGER.info("Database connection still alive! continue...");
    			} else {
    			    LOGGER.info("Database connection is lost! trying to reconnect ...");
    			    db_con = DriverManager.getConnection(url,db_username,db_password);
    			    if (!db_con.isClosed()) {
    			        LOGGER.info("Success reconnect to the Database!");
    			    } else {
    			        LOGGER.info("Database reconnection failure !!!");
    			    }
    			}
    			//2.创建statement类对象，用来执行SQL语句！！
			    Statement statement = db_con.createStatement();
    			//3.ResultSet类，用来存放获取的结果集！！
    			ResultSet rs = statement.executeQuery(sql);
    			LOGGER.info("------------------------------------------------------------------------------------------------");  
    			LOGGER.info("| "+ "DEK" + "\t" +" | ");  
    			LOGGER.info("------------------------------------------------------------------------------------------------");  			             
    			String s_DEK = null;
    		
    			while(rs.next()){
    				//获取stuname这列数据
    				s_DEK = rs.getString("dekcode");
    				LOGGER.info("| "+ s_DEK + "\t" +" | ");
    				if(s_DEK != null){
        				byte[] ciphertextBytes = Base64.getDecoder().decode(s_DEK); // Base64 decode
        				LOGGER.info("Initial: DEK after Base64 decode: "+ new String(ciphertextBytes));
        				// byte[] ret_tmp = encryptionSdk.decryptData(this.provider, ByteBuffer.wrap(ciphertextBytes));
        				// LOGGER.info("Initial: DEK after decryption: "+ new String(ret_tmp));
        				this.setEnryptDataKey(ciphertextBytes); // store the encrypted DEK without Base64
    			    }
  
    			}
    			rs.close();
			}
			db_con.close();
		} catch(ClassNotFoundException e) {   
				//数据库驱动类异常处理
				LOGGER.info("Sorry,can`t find the Driver!");   
				e.printStackTrace();   
		} catch(SQLException e) {
				//数据库连接失败异常处理
				e.printStackTrace();  
		}catch (Exception e) {
			// TODO: handle exception
				e.printStackTrace();
		}finally{
				LOGGER.info("Initial: 数据库数据成功获取！");
		}

     }

    public boolean IsEmpty(String sql) {
        try {
			if(!db_con.isClosed()) {
				LOGGER.info("Database connection still alive! continue...");
			} else {
			    LOGGER.info("Database connection is lost! trying to reconnect ...");
			    db_con = DriverManager.getConnection(url,db_username,db_password);
			    if (!db_con.isClosed()) {
			        LOGGER.info("Success reconnect to the Database!");
			    } else {
			        LOGGER.info("Database reconnection failure !!!");
			        return false;
			    }
			}
			//2.创建statement类对象，用来执行SQL语句！！
			Statement statement = db_con.createStatement();
// 			//要执行的SQL语句
// 			String sql = "select * from activationDB.DEK";
			//3.ResultSet类，用来存放获取的结果集！！
			ResultSet rs = statement.executeQuery(sql);
			if (rs.next()) {
			    LOGGER.info("Found Record from DB 666!");
			    rs.close();
			    db_con.close();
			    return true;
			} else {
			    LOGGER.info("No record found from DB :(");
			    rs.close();
			    db_con.close();
			    return false;
			}
			
        } catch(SQLException e) {
				//数据库连接失败异常处理
				e.printStackTrace();  
		}catch (Exception e) {
			// TODO: handle exception
				e.printStackTrace();
		}finally{
				LOGGER.info("finish isEmpty function");
		}
		return true;
    }

    public void insterDB(String sql) {
        try {
			if(!db_con.isClosed()) {
				LOGGER.info("Database connection still alive! continue...");
			} else {
			    LOGGER.info("Database connection is lost! trying to reconnect ...");
			    db_con = DriverManager.getConnection(url,db_username,db_password);
			    if (!db_con.isClosed()) {
			        LOGGER.info("Success reconnect to the Database!");
			    } else {
			        LOGGER.info("Database reconnection failure !!!");
			        return ;
			    }
			}
			//2.创建statement类对象，用来执行SQL语句！！
			Statement statement = db_con.createStatement();
			//3.ResultSet类，用来存放获取的结果集！！
			statement.executeUpdate(sql);
			db_con.close();
        } catch(SQLException e) {
				//数据库连接失败异常处理
				e.printStackTrace();  
		}catch (Exception e) {
			// TODO: handle exception
				e.printStackTrace();
		}finally{
				LOGGER.info("finish isEmpty function");
		}
    }     
     /*
      * build single CMK provider, no datakey generated, need to use 
      * setEnryptDataKey to load the datakey from database or S3 generated before...
      */
    private static MasterKeyProvider<?> InitialSingleProvider(final String keyId) {
        KmsMasterKey masterKey1 = new KmsMasterKeyProvider(keyId).getMasterKey(keyId);
        return MultipleProviderFactory.buildMultiProvider(masterKey1);
    }


    private static final ObjectMapper mapper = new ObjectMapper(); //add by bob for fixed content encryption;

    public String encrypt(JsonNode data) throws Exception {
		try {
            LOGGER.info("================Start encrypt function ==========================");
            FormData formValues = MAPPER.treeToValue(data, FormData.class);
            
            //We can access specific form fields using values in the parsed FormData object.
            LOGGER.info("Got the IMEI to be verified " + formValues.orderid);
            LOGGER.info("Got form new IMEI : " + formValues.name);
            LOGGER.info("Got form LoopNumber : " + formValues.email);
            
            
            // encrypt the whole formValue, old logic
            // byte[] plaintext = MAPPER.writeValueAsBytes(formValues);
            // LOGGER.info("plaintext from jason " + plaintext);
            // String carJson = new String(plaintext);
            // LOGGER.info("carJson coverted from plaintext " + carJson);

            // encrypt the IMEI, new logic. get the IMEI
            if (formValues.name.length() > 0) { // if there is a new generated IMEI, encrypt it and put it into the DB
                byte[] plaintext = MAPPER.writeValueAsBytes(formValues.name);
                LOGGER.info("plaintext of IMEI from jason " + plaintext);
                String carJson = new String(plaintext);
                LOGGER.info("carJson IMEI coverted from plaintext " + carJson);   
                
                // get the datakey with single CMK Provider
                //this.provider = InitialSingleProvider("arn:aws:kms:us-east-2:484626021127:key/1f154dd3-1d7c-4ee0-aa29-01cf206e1a99"); //CMK in master side
                //LOGGER.info("this.cypherDataKeyStr:" + new String(this.cypherDataKey_P.array()) );
                
                // ------------------ no cache for DEK decrption
                CryptoResult<byte[], ?> ret_tmp;
                long millisStart = Calendar.getInstance().getTimeInMillis();
                LOGGER.info("Start to decrypt DEK from member variable, DEK before decryption is : " + new String(cypherDataKey_P.array())); 
     
                // LOGGER.info("Start to decrypt DEK  " + millisStart); // calculate the time consumed for DEK decryption via KMS SDK
                
                // for (int x=1; x <= 2; x++)
                // {
                //     ret_tmp = encryptionSdk.decryptData(this.provider, cypherDataKey_P.array());
                // }
                long millisEnd = Calendar.getInstance().getTimeInMillis();
                // LOGGER.info("finish decrypt DEK " + millisEnd); 
                // LOGGER.info("Time consumed for DEK decryption via SDK: " + (millisEnd-millisStart) +"ms"); // calculate the time consumed for DEK decryption via KMS SDK
                
                // ------------------------ use cache for DEK decryption
                /*
                 * Security thresholds
                 *   Max entry age is required. 
                 *   Max messages (and max bytes) per entry are optional
                 */
                // Cache capacity (maximum number of entries) is required
                int MAX_CACHE_SIZE = 10; 
                
                CryptoMaterialsCache cache = new LocalCryptoMaterialsCache(MAX_CACHE_SIZE);
                int MAX_ENTRY_AGE_SECONDS = 100;
                int MAX_ENTRY_MSGS = 10;
                       
                //Create a caching CMM
                CryptoMaterialsManager cachingCmm =
                    CachingCryptoMaterialsManager.newBuilder().withMasterKeyProvider(this.provider)
                                                 .withCache(cache)
                                                 .withMaxAge(MAX_ENTRY_AGE_SECONDS, TimeUnit.SECONDS)
                                                 .withMessageUseLimit(MAX_ENTRY_MSGS)
                                                 .build();
               
                // When the call to encryptData specifies a caching CMM,
                // the encryption operation uses the data key cache
                //
                
                millisStart = Calendar.getInstance().getTimeInMillis();
                byte[] message;
                for (int x=1; x <= 10; x++)
                {
                    message = encryptionSdk.decryptData(cachingCmm, cypherDataKey_P.array()).getResult();
                }
                
                millisEnd = Calendar.getInstance().getTimeInMillis();
                LOGGER.info("Time consumed for DEK decryption via SDK with Cache: " + (millisEnd-millisStart) +"ms"); // calculate the time consumed for DEK decryption via KMS SDK
                // ------------------ end of cache sdk
                
                CryptoResult<byte[], ?> result = new AwsCrypto().decryptData(this.provider, cypherDataKey_P.array());
                LOGGER.info("decrypt: Got the plantext DEK with Provider " + new String(result.getResult()) );
    
                // encrypt and base64 code for the content to be sent to SQS, store in DB later;
                ByteBuffer plainTextKey = ByteBuffer.wrap(result.getResult()); 
                String encryptStr = encrypt(carJson, makeKey(plainTextKey));
                LOGGER.info("encrypted and base64code :" + encryptStr + ":" + encryptStr.length());
    
                //copy the string to global value, tmp
                this.cypherText1_ = encryptStr;
                LOGGER.info("global value of cypherText1_:" + this.cypherText1_ + ":" + this.cypherText1_.length());
    
                // store the encrypt IMEI into database;
                String insertSQL = new String("INSERT INTO activationDB.IMEI(IMEICode) VALUES('"+ encryptStr +"');");
                LOGGER.info("The insert SQL is :" + insertSQL);
                insterDB(insertSQL); // insert the DEK with base64 coded into database;
    
                return encryptStr;
            }
            
            if (formValues.orderid.length() > 0) { // if there is a IMEI need to be verified from DB, go this steps
                // step 1, encrypt the IMEI
                // step 1.1 get the plaintext DEK via decryption; 
                CryptoResult<byte[], ?> result = new AwsCrypto().decryptData(this.provider, cypherDataKey_P.array());
                LOGGER.info("decrypt: Got the plantext DEK with Provider " + new String(result.getResult()) );
    
                // step 1.2 conver the plaintext key into ByteBuffer;
                ByteBuffer plainTextKey = ByteBuffer.wrap(result.getResult()); 
                // step 1.3 encrypt the IMEI
                byte[] tmptext = MAPPER.writeValueAsBytes(formValues.orderid);
                LOGGER.info("IMEI to be verified [byte]:" + tmptext);
                String IMEI2BeVerified = new String(tmptext);
                LOGGER.info("IMEI to be verified [String]:" + IMEI2BeVerified); 
                
                String encryptString = encrypt(IMEI2BeVerified, makeKey(plainTextKey));
                // String encryptString = encrypt(formValues.orderid, makeKey(plainTextKey));
                LOGGER.info("IMEI encrypted and base64code :" + encryptString + ":" + encryptString.length());
                  
                // step 2, query DB for the encrypted IMEI
            	String IMEIsql = "select * from activationDB.IMEI where IMEICode = '" + encryptString +"';";
            	LOGGER.info("The SQL to verify the IMEI is :" + IMEIsql);
			    boolean IMEIIsThere = IsEmpty(IMEIsql);
			    if (IMEIIsThere) {
			        LOGGER.info("Found the matched IMEI from database. 666!!!");
			        String ret = "activated";
			        return ret;
			    }
			    return encryptString;

            }
            

		} catch(Exception e) {
		   e.printStackTrace();
		} 
        // end of 102
 
        //LOGGER.info("return base64 encoded is " + ciphertext);
        return null;
    }

    public String encrypt_s(String data) throws Exception {
		try {
            //String carJson =    "{ \"brand\" : \"Mercedes\", \"doors\" : 1234567890 }";
            //JsonNode root = mapper.readTree(new File("/home/ec2-user/environment/data.json")); //add by bob for fixed content encryption;
            //FormData formValues = MAPPER.treeToValue(root, FormData.class);
        
            // FormData formValues = MAPPER.treeToValue(data, FormData.class);
            
            // //We can access specific form fields using values in the parsed FormData object.
            // LOGGER.info("Got form submission for order " + formValues.orderid);
    
            // byte[] plaintext = MAPPER.writeValueAsBytes(formValues);
            LOGGER.info("encrypt_s: plaintext from jason " + data);
            String carJson = data;
            LOGGER.info("encrypt_s: carJson coverted from plaintext " + carJson);
            
            
            /*
            *   new update 1001，refer to https://github.com/uzresk/aws-examples/blob/master/src/main/java/jp/gr/java_conf/uzresk/aws/kms/simple/KmsExample.java
            */
        		final String dataStr = "abcdefghijk1234567890";

            // get the datakey with Provider
            // LOGGER.info("this.cypherDataKeyStr:" + new String(this.cypherDataKey_P.array()) );
            // CryptoResult<byte[], ?> result = new AwsCrypto().decryptData(this.provider, cypherDataKey_P.array());
            // LOGGER.info("decrypt: Got the plantextKey with Provider " + new String(result.getResult()) );

            // get the datakey with single CMK Provider
            this.provider = InitialSingleProvider("arn:aws:kms:us-east-2:484626021127:key/1f154dd3-1d7c-4ee0-aa29-01cf206e1a99"); //CMK in master side
            LOGGER.info("this.cypherDataKeyStr:" + new String(this.cypherDataKey_P.array()) );
            CryptoResult<byte[], ?> result = new AwsCrypto().decryptData(this.provider, cypherDataKey_P.array());
            LOGGER.info("decrypt: Got the plantextKey with Provider " + new String(result.getResult()) );
            

            // encrypt and base64 code for the content to be sent to SQS;
            ByteBuffer plainTextKey = ByteBuffer.wrap(result.getResult()); 
            String encryptStr = encrypt(carJson, makeKey(plainTextKey));
            LOGGER.info("encrypted and base64code :" + encryptStr + ":" + encryptStr.length());

            //copy the string to global value
            this.cypherText1_ = encryptStr;
            LOGGER.info("global value of cypherText1_:" + this.cypherText1_ + ":" + this.cypherText1_.length());

    		// /////////////////////////////////////////////////////////////////////
    
            // set the vaule of global cypherDataKey_A
    // 		ByteBuffer encryptedKey = dataKeyResult.getCiphertextBlob();
    // 		this.cypherDataKey_A = encryptedKey.duplicate();// for global variable
    // 		LOGGER.info(" cypherDataKey_A:" + new String(this.cypherDataKey_A.array()) );
    		
    		// decrypt data    
    // 		DecryptRequest decryptRequest = new DecryptRequest()
    // 				.withCiphertextBlob(encryptedKey);
    				
    // 		plainTextKey = kms.decrypt(decryptRequest).getPlaintext();// get plain text key from encryptedKey, to be replaced with provider.
    // 		LOGGER.info("decrypted plainTextKey[" + plainTextKey.array() + "]");
    //         String decryptStr = decrypt(encryptStr, makeKey(plainTextKey));
    //         LOGGER.info("decrypted[" + decryptStr + "]");
    //         //this.cypherText_ = decryptStr;

            /* end of 1001
             *---------------------------------------------------
             */
            

            return encryptStr;

		} catch(Exception e) {
		   e.printStackTrace();
		} 
        // end of 102
 
        //LOGGER.info("return base64 encoded is " + ciphertext);
        return null;
    }

    public String decrypt_s(String ciphertext) throws Exception {
        LOGGER.info("decrypt: Got the ciphertext : " + ciphertext);

        // get the datakey with single CMK Provider
        this.provider = InitialSingleProvider("arn:aws:kms:us-west-2:484626021127:key/5565682b-a453-46e0-b071-8c3401638ae8"); //CMK in standby side
        
        CryptoResult<byte[], ?> result = new AwsCrypto().decryptData(this.provider, this.cypherDataKey_P.array());
        LOGGER.info("decrypt: cypherDataKey_P before decryptData " + new String(this.cypherDataKey_P.array()) );
        LOGGER.info("decrypt: Got the plantextKey with decryptData " + new String(result.getResult()) );

        //start to decrypt 
        LOGGER.info("decrypt: ciphertext before decode " + ciphertext);

        ByteBuffer plainTextKey_P = ByteBuffer.wrap(result.getResult()); 
        // refer: ByteBuffer buf = ByteBuffer.wrap(bytes);
        LOGGER.info("decrypted plainTextKey_P:" + new String( plainTextKey_P.array()) );
        String decryptStr_P = decrypt(ciphertext, makeKey(plainTextKey_P));
        LOGGER.info("decryptStr_P:" + decryptStr_P );
        // String decryptStr_A = decrypt(ciphertext, makeKey(plainTextKey_A));
        // LOGGER.info("decryptStr_A:" + decryptStr_A );

        /*
         * compare the content encrypted with the key generated and 
         * the content encrypted with the key restored from Provider
         * 2001 begin
         */

        // use the plainTextKey_P restored from cyperDataKey_P to encrypt the content again.
        String cypherTextAgain = encrypt(decryptStr_P, makeKey(plainTextKey_P));
        
        LOGGER.info("cypherText1_:" + this.cypherText1_ + ":" + this.cypherText1_.length());
//        LOGGER.info("cypherTextAgain:" + cypherTextAgain );
        LOGGER.info("cypherTextAgain:" + cypherTextAgain + ":" + cypherTextAgain.length());

        // compare cypherText1 and cypherText2
        int compare = cypherText1_.compareTo( cypherTextAgain );
        LOGGER.info("!!!the string compare result is:" + compare );
        

        /*
         * end of 2001
         */

       
        return decryptStr_P;
        
    }

    public JsonNode decrypt(String ciphertext) throws Exception {
        //        byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext);
                LOGGER.info("decrypt: Got the ciphertext : " + ciphertext);
                //CryptoResult<byte[], ?> result = new AwsCrypto().decryptData(provider, ciphertextBytes);
                
            //     DecryptRequest decryptRequest = new DecryptRequest().withCiphertextBlob(this.cypherDataKey_A);
            // 	ByteBuffer plainTextKey_A = kms.decrypt(decryptRequest).getPlaintext();
            // 	LOGGER.info("decrypted plainTextKey_A:" + plainTextKey_A.array() );
 
                this.provider = InitialSingleProvider("arn:aws:kms:us-west-2:484626021127:key/5565682b-a453-46e0-b071-8c3401638ae8"); //CMK in standby side
 
                // get the datakey with Provider
                //byte[] cyperDataKey_P = this.cypherDataKey_P.array();
                CryptoResult<byte[], ?> result = new AwsCrypto().decryptData(this.provider, this.cypherDataKey_P.array());
                LOGGER.info("decrypt: cypherDataKey_P before decryptData " + new String(this.cypherDataKey_P.array()) );
                LOGGER.info("decrypt: Got the plantextKey with decryptData " + new String(result.getResult()) );
        
                // Check that we have the correct type
                // if (!Objects.equals(result.getEncryptionContext().get(K_MESSAGE_TYPE), TYPE_ORDER_INQUIRY)) {
                //     throw new IllegalArgumentException("Bad message type in decrypted message");
                // }
        
                //start to decrypt 
                LOGGER.info("decrypt: ciphertext before decode " + ciphertext);
        
                ByteBuffer plainTextKey_P = ByteBuffer.wrap(result.getResult()); 
                // refer: ByteBuffer buf = ByteBuffer.wrap(bytes);
                LOGGER.info("decrypted plainTextKey_P:" + new String( plainTextKey_P.array()) );
                String decryptStr_P = decrypt(ciphertext, makeKey(plainTextKey_P));
                LOGGER.info("decryptStr_P:" + decryptStr_P );
                // String decryptStr_A = decrypt(ciphertext, makeKey(plainTextKey_A));
                // LOGGER.info("decryptStr_A:" + decryptStr_A );
        
                /*
                 * compare the content encrypted with the key generated and 
                 * the content encrypted with the key restored from Provider
                 * 2001 begin
                 */
        
                // use the plainTextKey_P restored from cyperDataKey_P to encrypt the content again.
                String cypherTextAgain = encrypt(decryptStr_P, makeKey(plainTextKey_P));
                
                LOGGER.info("cypherText1_:" + this.cypherText1_ + ":" + this.cypherText1_.length());
        //        LOGGER.info("cypherTextAgain:" + cypherTextAgain );
                LOGGER.info("cypherTextAgain:" + cypherTextAgain + ":" + cypherTextAgain.length());
        
                // compare cypherText1 and cypherText2
                int compare = cypherText1_.compareTo( cypherTextAgain );
                LOGGER.info("!!!the string compare result is:" + compare );
                
        
                /*
                 * end of 2001
                 */
        
               
                return MAPPER.readTree(decryptStr_P.getBytes());
                
            }
        

    private static MasterKeyProvider<?> getKeyProvider(KmsMasterKey masterKeyEast, KmsMasterKey masterKeyWest) {
         return MultipleProviderFactory.buildMultiProvider(masterKeyWest, masterKeyEast);
    }

	public static String encrypt(String src, Key key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {
        try {
    		Cipher cipher = Cipher.getInstance("AES");
    		cipher.init(Cipher.ENCRYPT_MODE, key);
    
    		byte[] enc = cipher.doFinal(src.getBytes());
    
    		return Base64.getEncoder().encodeToString(enc);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
	}

	public static String decrypt(String src, Key key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {

		try {
		    
    		byte[] decodeBase64src = Base64.getDecoder().decode(src);
    		LOGGER.info(new String(decodeBase64src));
    
    		Cipher cipher = Cipher.getInstance("AES");
    
    		cipher.init(Cipher.DECRYPT_MODE, key);
    		LOGGER.info(new String(cipher.doFinal(decodeBase64src)));
    		return new String(cipher.doFinal(decodeBase64src));
		} catch (Exception e) {
		    e.printStackTrace();
		}
		return null;
	}

	public static Key makeKey(ByteBuffer key) throws Exception{
	    try {
		    return new SecretKeySpec(getByteArray(key), "AES");
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	    return null;
	}
	
// 	public static byte[] getByteArray(ByteBuffer b) {
// 		byte[] byteArray = new byte[b.remaining()];
// 		b.get(byteArray);
// 		return byteArray;
// 	}
	public static byte[] getByteArray(ByteBuffer b) {
		byte[] byteArray = new byte[b.remaining()];
		b.get(byteArray);
		return b.array();
  }

  public int setEnryptDataKey(byte[] ciphertext) throws Exception {
    // this.cypherDataKey_P = ByteBuffer.wrap(ciphertext.getBytes("UTF-8"));
    this.cypherDataKey_P = ByteBuffer.wrap(ciphertext);
    return 1;
  }

  public String getEnryptDataKey( ) throws Exception {
    String tmp = new String(this.cypherDataKey_P.array());
    return tmp;

  }
}