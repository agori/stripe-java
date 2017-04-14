package com.stripe.exception;

public class SignatureVerificationException extends StripeException {

	private static final long serialVersionUID = 1L;

	private final String sigHeader;

	public SignatureVerificationException(String message, String sigHeader) {
		super(message, null, 0);
		this.sigHeader = sigHeader;
	}

	public String getSigHeader() {
		return sigHeader;
	}

}
