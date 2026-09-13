FROM itsafeaturemythic/mythic_python_base:latest

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

COPY [".", "/Mythic"]

WORKDIR /Mythic/

CMD ["python3", "main.py"]
