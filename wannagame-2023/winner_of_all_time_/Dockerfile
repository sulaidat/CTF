FROM ubuntu:23.04

RUN apt-get update ; \
 apt-get install -y socat

RUN apt-get update && apt-get -y upgrade

# custom
RUN apt-get install gdb wget binutils file -y

# pwntools
RUN apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential -y 
RUN apt install python3-pip -y
RUN apt install python3-pwntools -y
RUN apt install python3-ipython -y
# RUN pip install --upgrade pwntools

# For gdb - gef
RUN wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
RUN echo source ~/.gdbinit-gef.py >> ~/.gdbinit

WORKDIR /app

COPY winner_of_all_time flag /app/

RUN chmod +x /app/winner_of_all_time && \
    useradd -m nonroot && \
    chown -R nonroot:nonroot /app

USER nonroot

CMD socat \
       TCP-LISTEN:13337,reuseaddr,fork \
       EXEC:"/app/winner_of_all_time"
