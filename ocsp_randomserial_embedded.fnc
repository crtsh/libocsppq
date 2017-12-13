CREATE OR REPLACE FUNCTION ocsp_randomserial_embedded(
	issuer_cert				bytea,
	ocsp_url				text
) RETURNS text
AS $$
BEGIN
	RETURN ocsp_randomserial_check(encode(issuer_cert, 'base64'), ocsp_url);
END;
$$ LANGUAGE plpgsql STRICT;
