FROM python:3.9

WORKDIR /usr/src/app

RUN apt-get update -y
RUN apt-get install git gcc

RUN git clone https://github.com/volatilityfoundation/volatility3.git --branch v1.0.0 --single-branch

ENV VOL_PATH /usr/src/app/volatility3
COPY misc/volatility /usr/local/bin/
RUN chmod +x /usr/local/bin/volatility

COPY kernel_shellcode_library kernel_shellcode_library

COPY devmem2 devmem2

WORKDIR /usr/src/app/devmem2
RUN make shared
WORKDIR /usr/src/app

CMD ["sleep", "3600"]
