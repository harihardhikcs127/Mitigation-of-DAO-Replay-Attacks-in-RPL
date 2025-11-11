# ns3-dao-replay-mitigation

This is an **ns-3.45** simulation project that demonstrates a lightweight mitigation strategy against **DAO (Destination Advertisement Object) replay attacks** in RPL-based IoT networks.

This project was developed for the "Internet of Things" (CS366) course at the National Institute of Technology Karnataka, Surathkal.

The simulation models a network of sensors and a root node. A compromised sensor (Sensor 0) launches a DAO replay attack, and the root node implements a freshness validation mechanism to detect and reject the malicious packets.

## 📖 How It Works

The simulation is built using three custom ns-3 applications:

* **`DaoSenderApp` (Sensor):** Periodically sends DAO packets to the root. Each packet contains a unique sequence number and a high-resolution timestamp.
* **`DaoAttackerApp` (Compromised Sensor 0):** This app, running on Sensor 0, captures its own first legitimate DAO packet. It then launches a "replay storm," sending 100 copies of this captured packet to the root at a rapid interval (0.01s).
* **`DaoRootReceiverApp` (Root Node):** This is the mitigation logic. It listens for all DAO packets and validates each one using a hybrid freshness check:
    1.  **Sequence Check:** Rejects packets with old sequence numbers.
    2.  **Timestamp Check:** Rejects packets with identical or older timestamps.
    3.  **Burst Check:** Rejects packets that arrive too quickly after a valid packet (e.g., within a 0.2s threshold), which catches the replay storm.

At the end of the simulation, the root node prints a summary of total, accepted, and rejected packets to the console and logs the results to `dao_metrics.csv`.

## ⚙️ Prerequisites

* An Ubuntu-based system (or WSL on Windows)
* **ns-3.45** (The code is written for this version)
* Essential build tools: `g++`, `python3`, `cmake`, `git`
* The `libboost-dev` library: `sudo apt install libboost-dev`

## 🚀 How to Run

1.  **Download and set up ns-3.45.**
    ```bash
    wget [https://www.nsnam.org/releases/ns-allinone-3.45.tar.bz2](https://www.nsnam.org/releases/ns-allinone-3.45.tar.bz2)
    tar xjf ns-allinone-3.45.tar.bz2
    ```
2.  **Move the code** to the `scratch` folder:
    ```bash
    mv dao-replay-mitigation.cc ~/ns-allinone-3.45/ns-3.45/scratch/
    ```
3.  **Navigate** to the `ns-3` directory:
    ```bash
    cd ~/ns-allinone-3.45/ns-3.45/
    ```
4.  **Configure** the project:
    ```bash
    ./ns3 configure
    ```
5.  **Build** the project (this will take a few minutes):
    ```bash
    ./ns3 build
    ```
6.  **Run** the simulation!
    ```bash
    ./ns3 run scratch/dao-replay-mitigation
    ```

## 📊 Running Experiments

You can control the simulation using command-line arguments.

* **`--nSensors`**: Set the number of sensors. (Default: `3`)
* **`--simTime`**: Set the total simulation time in seconds. (Default: `25.0`)
* **`--enableAttacker`**: Turn the attacker on or off. (Default: `true`)

#### Example 1: Run with default settings (Attacker ON)

```bash
./ns3 run scratch/dao-replay-mitigation
```

#### Example 2: Run without the attacker (Attacker OFF)

```bash
./ns3 run "scratch/dao-replay-mitigation --enableAttacker=false"
```

#### Example 3: Run a larger simulation

```bash
./ns3 run "scratch/dao-replay-mitigation --nSensors=20 --simTime=60.0"
```
