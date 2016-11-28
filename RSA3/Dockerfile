FROM registry.cn-beijing.aliyuncs.com/hcamael/rsa:base
MAINTAINER Docker Hcamael <hcamael@vidar.club>

COPY rsa3.py /home/RSA/rsa3.py
COPY flag.py /home/RSA/flag.py
COPY flag /home/RSA/flag
RUN chmod +x /home/RSA/rsa3.py

USER rsa
EXPOSE 7002
CMD ["socat", "TCP4-LISTEN:7002,fork", "EXEC:\"python -u /home/RSA/rsa3.py\""]

