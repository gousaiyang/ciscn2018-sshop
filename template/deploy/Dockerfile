FROM python:2.7

RUN apt-get update

WORKDIR /app

COPY ./www /app

ADD requirement.pip ./

RUN pip install --upgrade pip
RUN pip install -r ./requirement.pip

RUN useradd ctf -m -p 23gtf8732tf7
RUN chown -R ctf:ctf /app
RUN echo CISCN{this_is_a_sample_flag} > /home/ctf/flag
RUN sudo --user ctf python sshop/models.py
RUN sudo --user ctf python main.py
