FROM ubuntu:latest

COPY bootstrap.env /bootstrap.env
COPY bootstrap.sh /bootstrap.sh
COPY start_shell.sh /start_shell.sh
RUN chmod +x /start_shell.sh
RUN chmod +x /bootstrap.sh
# SHELL ["/start_shell.sh"]

ENTRYPOINT ["/bootstrap.sh"]