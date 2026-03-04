# Задача по разработке номер 2.

## Условие задачи

Дано: ОС Linux, есть сетевой интерфейс. Необходимо написать две программы.

Первая программа (sniffer), которая будет:
1. считывать сетевые пакеты с него.
2. фильтровать их по заданному IP-адресу хоста.
3. Брать длину пакетов, а также 5-tuple и отправлять их на вторую программу (analyzer).

Вторая программа (analyzer) должна:
1. Принимать информацию о длинах пакетов и 5-tuple
2. Обновлять статистику принятых пакетов по каждому хосту в виде (IP-адрес, число пакетов,
число байтов).
3. Периодически печатать в командную строку IP-адрес с самым большим числом пакетов и IP-
адрес с самым большим числом байтов.
Программа должна работать в командной строке. Язык реализации Go или C. Возможно
использование фреймворков DPDK или библиотеки libpcap, но выбор остаётся за решающим

## Solution

### Usage
#### Build the analyzer and sniffer executables
```
go build -o sniffer cmd/sniffer/main.go
go build -o analyzer cmd/analyzer/main.go
```

#### Analyzer
Start the analyzer first (listens on ports 9000 and 8080):
```
./analyzer
```

The ananlyzer will:
* Listen for TCP connections from sniffers on port 9000
* Serve HTTP API on port 8080 at /stats endpoint
* Print top bytes and packets IPs statistics periodically on cmd

#### Sniffer 
Start the sniffer on another terminal:
```
sudo ./sniffer -i <network_interface> -ip <filter_ip> -addr localhost:9000
````

You can also omit -ip flag. It is equivalent to collecting stats from all IPs.