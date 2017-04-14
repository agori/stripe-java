package com.stripe.model;

import com.stripe.exception.SignatureVerificationException;

import java.util.ArrayList;
import java.util.List;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Webhook {
	public static final String EXPECTED_SCHEME = "v1";

	private static final Long DEFAULT_TOLERANCE = Long.valueOf(300);

	/**
	 * Returns an Event instance using the provided JSON payload. Throws a
	 * JsonSyntaxException if the payload is not valid JSON.
	 *
	 * @param payload the payload sent by Stripe.
	 * @return the Event instance
	 */
	public static Event createEventFromPayload(String payload) {
			Event event = StripeObject.PRETTY_PRINT_GSON.fromJson(payload, Event.class);
			return event;
	}

	/**
	 * Returns an Event instance using the provided JSON payload. Throws a
	 * JsonSyntaxException if the payload is not valid JSON, and a
	 * SignatureVerificationException if the signature verification fails for
	 * any reason.
	 *
	 * @param payload the payload sent by Stripe.
	 * @param sigHeader the contents of the signature header sent by Stripe.
	 * @param secret secret used to generate the signature.
	 * @return the Event instance
	 * @throws SignatureVerificationException if the verification fails.
	 */
	public static Event createEventFromPayload(String payload, String sigHeader, String secret) throws SignatureVerificationException {
			Event event = createEventFromPayload(payload);
			verifyHeader(payload, sigHeader, secret);
			return event;
	}

	/**
	 * Returns an Event instance using the provided JSON payload. Throws a
	 * JsonSyntaxException if the payload is not valid JSON, and a
	 * SignatureVerificationException if the signature verification fails for
	 * any reason.
	 *
	 * @param payload the payload sent by Stripe.
	 * @param sigHeader the contents of the signature header sent by Stripe.
	 * @param secret secret used to generate the signature.
	 * @param tolerance maximum difference allowed between the header's
	 *  timestamp and the current time
	 * @return the Event instance
	 * @throws SignatureVerificationException if the verification fails.
	 */
	public static Event createEventFromPayload(String payload, String sigHeader, String secret, Long tolerance) throws SignatureVerificationException {
			Event event = createEventFromPayload(payload);
			verifyHeader(payload, sigHeader, secret, tolerance);
			return event;
	}

	/**
	 * Verifies the signature header sent by Stripe. Throws a
	 * SignatureVerificationException if the verification fails for any reason.
	 *
	 * @param payload the payload sent by Stripe.
	 * @param sigHeader the contents of the signature header sent by Stripe.
	 * @param secret secret used to generate the signature.
	 * @throws SignatureVerificationException if the verification fails.
	 */
	public static void verifyHeader(String payload, String sigHeader, String secret) throws SignatureVerificationException {
		verifyHeader(payload, sigHeader, secret, DEFAULT_TOLERANCE);
	}

	/**
	 * Verifies the signature header sent by Stripe. Throws a
	 * SignatureVerificationException if the verification fails for any reason.
	 *
	 * @param payload the payload sent by Stripe.
	 * @param sigHeader the contents of the signature header sent by Stripe.
	 * @param secret secret used to generate the signature.
	 * @param tolerance maximum difference allowed between the header's
	 *  timestamp and the current time
	 * @throws SignatureVerificationException if the verification fails.
	 */
	public static void verifyHeader(String payload, String sigHeader, String secret, Long tolerance) throws SignatureVerificationException {
		// Get timestamp and signatures from header
		Long timestamp = getTimestamp(sigHeader);
		List<String> signatures = getSignatures(sigHeader, EXPECTED_SCHEME);
		if (timestamp == null) {
			throw new SignatureVerificationException("Unable to extract timestamp and signatures from header", sigHeader);
		}
		if (signatures.size() == 0) {
			throw new SignatureVerificationException("No signatures found with expected scheme", sigHeader);
		}

		// Compute expected signature
		String signedPayload = String.format("%d.%s", timestamp, payload);
		String expectedSignature;
		try {
			expectedSignature = computeSignature(signedPayload, secret);
		} catch (Exception e) {
			throw new SignatureVerificationException("Unable to compute signature for payload", sigHeader);
		}

		// Check if expected signature is found in list of header's signatures
		Boolean signatureFound = false;
		for (String signature : signatures) {
			if (Util.secureCompare(expectedSignature, signature)) {
				signatureFound = true;
				break;
			}
		}
		if (!signatureFound) {
			throw new SignatureVerificationException("No signatures found matching the expected signature for payload", sigHeader);
		}

		// Check tolerance
		if ((tolerance > 0) && (timestamp < (Util.getTimeNow() - tolerance))) {
			throw new SignatureVerificationException("Timestamp outside the tolerance zone", sigHeader);
		}
	}

	/**
	 * Extracts the timestamp in a signature header.
	 *
	 * @param sigHeader the signature header
	 * @return the timestamp contained in the header.
	 */
	private static Long getTimestamp(String sigHeader) {
		String[] items = sigHeader.split(",");

		for (String item : items) {
			String[] itemParts = item.split("=", 2);
			if (itemParts[0].equals("t")) {
				return Long.valueOf(itemParts[1]);
			}
		}

		return null;
	}

	/**
	 * Extracts the signatures matching a given scheme in a signature header.
	 *
	 * @param sigHeader the signature header
	 * @param scheme the signature scheme to look for.
	 * @return the list of signatures matching the provided scheme.
	 */
	private static List<String> getSignatures(String sigHeader, String scheme) {
		List<String> signatures = new ArrayList<String>();
		String[] items = sigHeader.split(",");

		for (String item : items) {
			String[] itemParts = item.split("=", 2);
			if (itemParts[0].equals(scheme)) {
				signatures.add(itemParts[1]);
			}
		}

		return signatures;
	}

	/**
	 * Computes the signature for a given payload and secret.
	 *
	 * The current scheme used by Stripe ("v1") is HMAC/SHA-256.
	 *
	 * @param payload the payload to sign.
	 * @param secret the secret used to generate the signature.
	 * @return the signature as a string.
	 */
	private static String computeSignature(String payload, String secret) throws NoSuchAlgorithmException, InvalidKeyException {
		return Util.computeHmacSHA256(secret, payload);
	}

	public static final class Util {
		/**
		 * Computes the HMAC/SHA-256 code for a given key and message.
		 *
		 * @param secret the key used to generate the code.
		 * @param message the message.
		 * @return the code as a string.
		 */
		public static String computeHmacSHA256(String key, String message) throws NoSuchAlgorithmException, InvalidKeyException {
			Mac hasher = Mac.getInstance("HmacSHA256");
			hasher.init(new SecretKeySpec(key.getBytes(), "HmacSHA256"));
			byte[] hash = hasher.doFinal(message.getBytes());
			String result = "";
			for (byte b : hash) {
				result += Integer.toString((b & 0xff) + 0x100, 16).substring(1);
			}
			return result;
		}

		/**
		 * Compares two strings for equality. The time taken is independent of the
		 * number of characters that match.
		 *
		 * @param a one of the strings to compare.
		 * @param b the other string to compare.
		 * @return true if the strings are equal, false otherwise.
		 */
		public static boolean secureCompare(String a, String b) {
			byte[] digesta = a.getBytes();
			byte[] digestb = b.getBytes();

			if (digesta.length != digestb.length) {
				return false;
			}

			int result = 0;
			for (int i = 0; i < digesta.length; i++) {
				result |= digesta[i] ^ digestb[i];
			}
			return result == 0;
		}

		/**
		 * Returns the current UTC timestamp in seconds.
		 *
		 * @return the timestamp as a Long.
		 */
		public static Long getTimeNow() {
			long time = (long)(System.currentTimeMillis() / 1000L);
			return time;
		}
	}
}
