# Zero-OS air-gapped verification container for NLTP v1.6.0 NIST/IETF KAT suite
FROM scratch
COPY build/nltp_kat /nltp_kat
ENTRYPOINT ["/nltp_kat"]
