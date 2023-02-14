FROM python:3.9

WORKDIR /usr/src/app

RUN apt-get update -y
RUN apt-get install git gcc

RUN git clone https://github.com/volatilityfoundation/volatility3.git --branch v2.4.0 --single-branch

ENV VOL_PATH /usr/src/app/volatility3
COPY misc/volatility /usr/local/bin/
RUN chmod +x /usr/local/bin/volatility

COPY devmem2 devmem2

WORKDIR /usr/src/app/devmem2
RUN make shared
WORKDIR /usr/src/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY kernel_shellcode_library kernel_shellcode_library

COPY c2 c2

COPY *.py ./

COPY templates templates

CMD ["python", "app.py"]
