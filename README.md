<img src="logo.png" align="center" height="30%" width="30%" >

This keylogger (`curious_owl`) is for educational and research purposes only. By using this software, you agree that you will not 
use it for any harmful, unethical, or illegal activities. The developer does not condone or support the use of this 
software for malicious purposes, such as stealing personal data, infringing on privacy, or engaging in any 
unauthorized surveillance.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


## How to use it.
* Compile and run the keylogger
```shell
cargo run 
```
* Run Server
```shell
cd python_server
virtual venv
source venv/bin/activate
pip install .
flask run
```

For more information type:
```shell
curious_owl -h
```

```
Keylogger to spy on you.

Usage: curious_owl [OPTIONS] [end-point]

Arguments:
  [end-point]  Endpoint to send keystrokes to. [default: http://127.0.0.1:5000/endpoint]

Options:
  -i <interval>      interval in seconds to send data back. [default: 10]
  -h, --help         Print help

```