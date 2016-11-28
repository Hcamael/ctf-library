FROM registry.cn-beijing.aliyuncs.com/hcamael/rsa:base
MAINTAINER Docker Hcamael <hcamael@vidar.club>

COPY rsa2.py /home/RSA/rsa2.py
COPY flag.py /home/RSA/flag.py
COPY flag /home/RSA/flag
RUN chmod +x /home/RSA/rsa2.py

USER rsa
EXPOSE 7001
CMD ["socat", "TCP4-LISTEN:7001,fork", "EXEC:\"python -u /home/RSA/rsa2.py\""]
