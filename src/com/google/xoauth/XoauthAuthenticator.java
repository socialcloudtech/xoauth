/* Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.xoauth;

import java.security.Provider;
import java.security.Security;
import java.util.Properties;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.URLName;

import net.oauth.OAuthConsumer;

import com.sun.mail.imap.IMAPSSLStore;
import com.sun.mail.smtp.SMTPTransport;
import com.sun.mail.util.BASE64EncoderStream;

/**
 * Performs XOAUTH authentication.
 * 
 * <p>
 * Before using this class, you must call {@code initialize} to install the XOAUTH SASL provider.
 */
public class XoauthAuthenticator {

	static {
		Security.addProvider(new XoauthProvider());
	}

	public static final class XoauthProvider extends Provider {

		private static final long serialVersionUID = 1L;

		public XoauthProvider() {
			super("Google Xoauth Provider", 1.0, "Provides the Xoauth experimental SASL Mechanism");
			put("SaslClientFactory.XOAUTH", "com.google.xoauth.XoauthSaslClientFactory");
		}
	}

	/**
	 * Connects and authenticates to an IMAP server with XOAUTH. You must have called {@code initialize}.
	 * 
	 * @param host
	 *            Hostname of the imap server, for example {@code imap.googlemail.com}.
	 * @param port
	 *            Port of the imap server, for example 993.
	 * @param userEmail
	 *            Email address of the user to authenticate, for example {@code xoauth@gmail.com}.
	 * @param oauthToken
	 *            The user's OAuth token.
	 * @param oauthTokenSecret
	 *            The user's OAuth token secret.
	 * @param consumer
	 *            The application's OAuthConsumer. For testing, use {@code getAnonymousConsumer()}.
	 * @param debug
	 *            Whether to enable debug logging on the IMAP connection.
	 * 
	 * @return An authenticated IMAPSSLStore that can be used for IMAP operations.
	 */
	public static IMAPSSLStore connectToImap(String host, int port, String userEmail, String oauthToken,
			String oauthTokenSecret, OAuthConsumer consumer, boolean debug) throws Exception {
		Properties props = new Properties();
		props.put("mail.imaps.sasl.enable", "true");
		props.put("mail.imaps.sasl.mechanisms", "XOAUTH");
		props.put(XoauthSaslClientFactory.OAUTH_TOKEN_PROP, oauthToken);
		props.put(XoauthSaslClientFactory.OAUTH_TOKEN_SECRET_PROP, oauthTokenSecret);
		props.put(XoauthSaslClientFactory.CONSUMER_KEY_PROP, consumer.consumerKey);
		props.put(XoauthSaslClientFactory.CONSUMER_SECRET_PROP, consumer.consumerSecret);
		Session session = Session.getInstance(props);
		session.setDebug(debug);

		final URLName unusedUrlName = null;
		IMAPSSLStore store = new IMAPSSLStore(session, unusedUrlName);

		// System.out.println(host + " " + port + " " + userEmail);

		store.connect(host, port, userEmail, "");
		return store;
	}

	/**
	 * Connects and authenticates to an SMTP server with XOAUTH. You must have called {@code initialize}.
	 * 
	 * @param host
	 *            Hostname of the smtp server, for example {@code smtp.googlemail.com}.
	 * @param port
	 *            Port of the smtp server, for example 587.
	 * @param userEmail
	 *            Email address of the user to authenticate, for example {@code xoauth@gmail.com}.
	 * @param oauthToken
	 *            The user's OAuth token.
	 * @param oauthTokenSecret
	 *            The user's OAuth token secret.
	 * @param consumer
	 *            The application's OAuthConsumer. For testing, use {@code getAnonymousConsumer()}.
	 * @param debug
	 *            Whether to enable debug logging on the connection.
	 * 
	 * @return An authenticated SMTPTransport that can be used for SMTP operations.
	 */
	public static SMTPTransport connectToSmtp(String host, int port, String userEmail, String oauthToken,
			String oauthTokenSecret, OAuthConsumer consumer, boolean debug) throws Exception {
		Properties props = new Properties();
		props.put("mail.smtp.ehlo", "true");
		props.put("mail.smtp.auth", "false");
		props.put("mail.smtp.starttls.enable", "true");
		props.put("mail.smtp.starttls.required", "true");
		props.put("mail.smtp.sasl.enable", "false");
		Session session = Session.getInstance(props);
		session.setDebug(debug);

		final URLName unusedUrlName = null;
		SMTPTransport transport = new SMTPTransport(session, unusedUrlName);
		// If the password is non-null, SMTP tries to do AUTH LOGIN.
		final String emptyPassword = null;
		transport.connect(host, port, userEmail, emptyPassword);

		/*
		 * I couldn't get the SASL infrastructure to work with JavaMail 1.4.3; I don't think it was ready yet in that
		 * release. So we'll construct the AUTH command manually.
		 */
		XoauthSaslResponseBuilder builder = new XoauthSaslResponseBuilder();
		byte[] saslResponse = builder.buildResponse(userEmail, XoauthProtocol.SMTP, oauthToken, oauthTokenSecret,
				consumer);
		saslResponse = BASE64EncoderStream.encode(saslResponse);
		transport.issueCommand("AUTH XOAUTH " + new String(saslResponse), 235);
		return transport;
	}

	public static IMAPSSLStore getIMAPStore(String email, String password, String imap, int port, boolean debug)
			throws MessagingException {
		Properties props = new Properties();

		Session session = Session.getInstance(props);
		session.setDebug(debug);

		IMAPSSLStore store = new IMAPSSLStore(session, null);

		store.connect(imap, port, email, password);
		return store;
	}

	public static SMTPTransport getSMTPTransport(String email, String password, String host, int port, boolean debug)
			throws MessagingException {
		Properties props = new Properties();
		props.put("mail.smtp.auth", "true");
		props.put("mail.smtp.starttls.enable", "true");
		Session session = Session.getInstance(props);
		session.setDebug(debug);

		final URLName unusedUrlName = null;
		SMTPTransport transport = new SMTPTransport(session, unusedUrlName);
		transport.connect(host, port, email, password);
		return transport;
	}

	/**
	 * Authenticates to IMAP with parameters passed in on the commandline.
	 */
	public static void main(String args[]) throws Exception {
		// String email = "";
		// String oauthToken = "";
		// String oauthTokenSecret = "";
		// IMAPSSLStore imapSslStore = XoauthAuthenticator.connectToImap("imap.googlemail.com", 993, email, oauthToken,
		// oauthTokenSecret, new OAuthConsumer("", "", "", null));
		// System.out.println("Successfully authenticated to IMAP.\n");
		// imapSslStore.close();

		// String email = "";
		// String oauthToken = "";
		// String oauthTokenSecret = "";
		// SMTPTransport smtpTransport = connectToSmtp("smtp.googlemail.com", 587, email, oauthToken, oauthTokenSecret,
		// getAnonymousConsumer());
		// System.out.println("Successfully authenticated to SMTP.");
		// smtpTransport.close();
	}
}
