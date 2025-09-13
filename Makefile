VENV = .venv
VENV_PYTHON3 = $(VENV)/bin/python3

ADMIN ?= test:testpass
PROGRAM ?= ./client

all: venv deps client

# Setup Python Virtual Environment
venv: $(VENV_PYTHON3)
$(VENV_PYTHON3):
	python3 -m venv "$(VENV)"

deps: venv
	$(VENV_PYTHON3) -m pip install -r requirements.txt

# Compile the C Client
client: client.c helper.c requests.c parson.c
	gcc -Wall -Wextra -g -o client client.c helper.c requests.c parson.c

# Clean build files
clean:
	rm -f client *.o

# Run the Python checker
A ?= --debug --admin "$(ADMIN)"
run: all
	$(VENV_PYTHON3) checker.py $(PROGRAM) $(A)
