
package example.handlers;

import static example.Utils.MAPPER;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.log4j.Logger;

import example.HTTPResponse;
import example.KMSRequestCountingLogAppender;
import example.encryption.EncryptDecrypt;

import com.amazonaws.services.sqs.AmazonSQS;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

@Singleton
public class SendHandler implements AJAXHandler {
    private static final Logger LOGGER = Logger.getLogger(SendHandler.class);

    private final String queueUrl;
    private final AmazonSQS sqs;
    private final EncryptDecrypt encryptDecrypt;

    @Inject
    public SendHandler(
            @Named("queueUrl") final String queueUrl,
            final AmazonSQS sqs,
            final EncryptDecrypt encryptDecrypt
    ) {
        this.queueUrl = queueUrl;
        this.sqs = sqs;
        this.encryptDecrypt = encryptDecrypt;
    }

    @Override public HTTPResponse handle(final JsonNode request) throws Exception {
        KMSRequestCountingLogAppender.resetCount();

        JsonNode data = request.findValue("data");

        String ciphertext = encryptDecrypt.encrypt(data);
        
        JsonNodeFactory nodeFactory = MAPPER.getNodeFactory();

        ObjectNode response = nodeFactory.objectNode();
        //update for CORS by Robert 20200211
        response.set("method.response.header.Access-Control-Allow-Headers",nodeFactory.textNode("'Content-Type,X-Amz-Date,Authorization,X-Api-Key'"));
        response.set("method.response.header.Access-Control-Allow-Methods",nodeFactory.textNode("'*'"));
        response.set("method.response.header.Access-Control-Allow-Origin",nodeFactory.textNode("'*'"));
        
        if (ciphertext.compareTo("activated") == 0 ) { // IMEI found in the DB
            response.set("kmsCallCount",nodeFactory.textNode("~~~~~~~~Activation: Success!!! Congratulations! 666! :) "));
        } else { // IMEI not found in DB
            response.set("kmsCallCount",nodeFactory.textNode("^^^^^^^^Activation: Sorry, please check your IMEI number again! : ( "));
        }
        response.set("status", nodeFactory.textNode("ok"));
        //response.set("kmsCallCount", nodeFactory.numberNode(KMSRequestCountingLogAppender.getCount()));

        // sqs.sendMessage(queueUrl, ciphertext); // stop sending SQS

        return HTTPResponse.jsonResponse(200, response);
    }
}
