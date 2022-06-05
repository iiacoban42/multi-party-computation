from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
from random import SystemRandom
from typing import Dict, List


@dataclass
class Wire(ABC):
    """Any kind of wire in the circuit."""

    is_output: bool
    """`True` if and only if the value of this wire should be made public after executing the circuit."""


@dataclass
class InputWire(Wire):
    """A wire that corresponds to a client's input."""

    owner_id: int
    """The ID of the client that owns the data for this wire."""


@dataclass
class AddWire(Wire):
    """The output wire of an integer addition gate that computes `A + B`."""

    wire_a_id: int
    """The wire corresponding to input `A`, as identified by that wire's index in the list of wires (i.e. circuit) that
    this wire is part of."""

    wire_b_id: int
    """The wire corresponding to input `B`, as identified by that wire's index in the list of wires (i.e. circuit) that
    this wire is part of."""


@dataclass
class ConstMultWire(Wire):
    """The output wire of a constant-multiplication gate that computes `c * A`."""

    c: int
    """The constant `c` to multiply with `A`."""

    wire_a_id: int
    """The wire corresponding to input `A`, as identified by that wire's index in the list of wires (i.e. circuit) that
    this wire is part of."""


@dataclass
class MultWire(Wire):
    """The output wire of a multiplication gate that computes `A * B`."""

    wire_a_id: int
    """The wire corresponding to input `A`, as identified by that wire's index in the list of wires (i.e. circuit) that
    this wire is part of."""

    wire_b_id: int
    """The wire corresponding to input `B`, as identified by that wire's index in the list of wires (i.e. circuit) that
    this wire is part of."""


class BGW:
    """Behavior of the BGW protocol."""

    @staticmethod
    def create_shares(rng: SystemRandom, secret: int, share_count: int, mod: int) -> List[int]:
        """Divides the [secret] into [share_count] additive secret shares under modulo [mod] using [rng] as a source of
        randomness."""
        shares = []
        for _ in range(share_count-1):
            shares.append(rng.randrange(mod))

        final_share = (secret - sum(shares)) % mod
        shares.append(final_share)
        return shares

    @staticmethod
    def recover_secret(shares: List[int], mod: int) -> int:
        """Reconstructs the secret that the additive secret [shares] make up under modulo [mod]."""
        return sum(shares) % mod

    @staticmethod
    def add(a_share: int, b_share: int, mod: int) -> int:
        """Adds the shares [a_share] and [b_share] together under modulo [mod]."""
        return (a_share + b_share) % mod

    @staticmethod
    def const_mult(c: int, a_share: int, mod: int) -> int:
        """Multiplies the share [a_share] with the constant [c] under modulo [mod]."""
        return (c * a_share) % mod

    @staticmethod
    def mult(is_alice: bool, x_share: int, y_share: int, z_share: int, a_prime: int, b_prime: int, mod: int) -> int:
        """Performs the masked multiplication corresponding to `A * B` using the formula from the slides, under modulo
        [mod]. The constant term is added only if [is_alice] is `True`."""

        res = a_prime * y_share + b_prime * x_share + z_share

        if is_alice:
            res += a_prime * b_prime

        return res % mod

    @staticmethod
    def run_circuit(clients: List[Client], mod) -> Dict[int, int]:
        """Makes the [clients] interactively compute their circuit by synchronously invoking their methods, and returns
        all outputs of the circuit."""

        for client in clients:
            client.set_clients(clients)
            client.local_setup()

        for client in clients:
            client.interactive_setup()

        progress = [-1 for _ in range(len(clients))]

        while True:
            if progress[0] is None:
                break
            for i, client in enumerate(clients):
                progress[i] = client.run_circuit_until_mult(progress[i]+1)

            for client in clients:
                client.interactive_setup()

        circuit = {}
        for client in clients:
            if circuit == {}:
                circuit = client.get_outputs()
            else:
                circuit = {k: (circuit.get(k, 0) + client.get_outputs().get(k, 0)) % mod for k in set(circuit)}

        return circuit


class TTP:
    """A trusted third party that can be trusted to generate Beaver triples."""

    def __init__(self, client_count: int, mod: int, rng: SystemRandom):
        """Initializes this [TTP], given the number of clients [client_count] participating in the protocol, the modulo
        [mod] to perform secret sharing under, and a source of randomness [rng]."""
        self.client_count = client_count
        self.mod = mod
        self.rng = rng
        self.triples = {}

    def _create_beaver_triple(self, gate_id: int, client_id: int) -> [int, int, int]:
        """Generate beaver triple and shares"""
        x = self.rng.randrange(self.mod)
        y = self.rng.randrange(self.mod)
        z = x*y % self.mod

        x_shares = BGW.create_shares(self.rng, x, self.client_count, self.mod)
        y_shares = BGW.create_shares(self.rng, y, self.client_count, self.mod)
        z_shares = BGW.create_shares(self.rng, z, self.client_count, self.mod)

        self.triples[gate_id] = [x_shares, y_shares, z_shares]

        client_share = [x_shares[client_id], y_shares[client_id], z_shares[client_id]]
        return client_share


    def get_beaver_triple(self, gate_id: int, client_id: int) -> [int, int, int]:
        """Returns shares of the Beaver triple for multiplication gate [gate_id] for [client_id]. Make sure that clients
        requesting shares for the same [gate_id] actually get shares of the same Beaver triple."""
        if gate_id in self.triples:

            return [self.triples[gate_id][0][client_id],
                    self.triples[gate_id][1][client_id],
                    self.triples[gate_id][2][client_id]]

        return self._create_beaver_triple(gate_id, client_id)



class Client:
    """A client in the BGW protocol."""

    def __init__(self, client_id: int, ttp: TTP, circuit: List[Wire], inputs: Dict[int, int], mod: int, rng: SystemRandom):
        """Constructs a new [Client], but does not do any significant computation yet. Here, [client_id] uniquely
        identifies this client, [ttp] is the TTP that will provide the client with shares of Beaver triples, [circuit]
        is the circuit that will be executed, [inputs] is a mapping from wire indices to this client's private input
        values, [mod] is the modulo under which the circuit is computed, and [rng] is the source of randomness used
        whenever possible."""
        self.client_id = client_id
        self.ttp = ttp
        self.circuit = circuit
        self.inputs = inputs
        self.mod = mod
        self.rng = rng
        self.clients = []
        self.output = {}

    def set_clients(self, clients: List[Client]):
        """Gives this client knowledge of the [Client]s that participate in the protocol."""
        self.clients = clients
        self.clients.sort(key=lambda x: x.client_id)

    def get_input_share(self, wire_id: int, requester_id: int) -> int:
        """Returns the share of this client's input at wire [wire_id] that they created for client [requester_id]. This
        client should validate that this request is sensible, but may assume that the requester is
        honest-but-curious."""
        if self.input_shares[wire_id] is not None:
            return self.input_shares[wire_id][requester_id]

    def local_setup(self):
        """Performs the local part of the setup, which consists of creating shares for this client's inputs."""
        self.input_shares = {}
        for wire_id, wire in enumerate(self.circuit):
            self.input_shares[wire_id] = [0 for _ in range(len(self.clients))]
        for (wire, private_value) in self.inputs.items():
            self.input_shares[wire] = BGW.create_shares(self.rng, private_value, len(self.clients), self.mod)

    def interactive_setup(self):
        """Performs the interactive part of the setup, which consist of retrieving shares of Beaver triples from the
        TTP and fetching the shares that other clients have created of their inputs for this client."""
        self.beaver_shares = {}
        self.peer_shares = {}

        for wire_id, wire in enumerate(self.circuit):
            if isinstance(wire, MultWire):
                self.beaver_shares[wire_id] = self.ttp.get_beaver_triple(wire_id, self.client_id)
            elif isinstance(wire, InputWire):
                self.input_shares[wire_id][self.client_id] = self.clients[wire.owner_id].get_input_share(wire_id, self.client_id)


    def get_masked_shares(self, wire_id: int) -> [int, int]:
        """Returns the masked shares `A - X` and `B - Y` that this client created for the multiplication at wire
        [wire_id]."""
        wire_a = self.circuit[wire_id].wire_a_id
        wire_b = self.circuit[wire_id].wire_b_id

        a = self.get_input_share(wire_a, self.client_id) - self.beaver_shares[wire_id][0]
        b = self.get_input_share(wire_b, self.client_id) - self.beaver_shares[wire_id][1]
        return [a, b]

    def get_output_share(self, wire_id: int) -> int:
        """Returns the share that this client calculated for the wire [wire_id], to be used to reconstruct the value of
        this wire. This client should validate that this request is sensible, but may assume that the requester is
        honest-but-curious."""
        gate = self.circuit[wire_id]

        output_share = 0
        if isinstance(gate, MultWire):
            masked_shares = self.get_masked_shares(wire_id)

            is_alice = (self.client_id == 0)

            output_share = BGW.mult(is_alice,
                                self.beaver_shares[wire_id][0],
                                self.beaver_shares[wire_id][1],
                                self.beaver_shares[wire_id][2],
                                masked_shares[0],
                                masked_shares[1],
                                self.mod
                                )

        elif isinstance(gate, AddWire):
            output_share = BGW.add(self.get_input_share(gate.wire_a_id, self.client_id),
                                   self.get_input_share(gate.wire_b_id, self.client_id),
                                   self.mod
                                   )

        elif isinstance(gate, ConstMultWire):
            output_share = BGW.const_mult(gate.c,
                                          self.get_input_share(gate.wire_a_id, self.client_id),
                                          self.mod
                                          )
        elif isinstance(gate, InputWire):
            output_share = self.get_input_share(wire_id, self.client_id)

        return output_share

    def run_circuit_until_mult(self, start_at_wire_id: int) -> int | None:
        """Runs the circuit starting at wire [start_at_wire_id] until it encounters a multiplication gate. If a
        multiplication gate is encountered, this client performs some local computation, and then returns the id of the
        wire it stopped at. This client may assume that the next time this method is invoked, it continues at the
        multiplication it left off at by performing the interactive part of the multiplication. After that, this client
        continues to run the circuit until it encounters another multiplication gate. If this client is done with the
        circuit, this function returns `None`."""

        for wire_id in range(start_at_wire_id, len(self.circuit)):
            if isinstance(self.circuit[start_at_wire_id], MultWire):
                self.output[wire_id] = self.get_output_share(wire_id)
                self.input_shares[wire_id][self.client_id] = self.output[wire_id]
                return wire_id
            else:
                self.output[wire_id] = self.get_output_share(wire_id)
                self.input_shares[wire_id][self.client_id] = self.output[wire_id]

        return None

    def get_outputs(self) -> Dict[int, int]:
        """Returns a dictionary from wire IDs to the reconstructed outputs at those wires, corresponding to all outputs
        of the circuit."""
        return self.output


def main():
    circuits = {
        "basic": [
            InputWire(is_output=False, owner_id=0),  # 0
            InputWire(is_output=False, owner_id=1),  # 1
            InputWire(is_output=False, owner_id=2),  # 2
            AddWire(is_output=False, wire_a_id=0, wire_b_id=1),  # 3
            ConstMultWire(is_output=False, c=6, wire_a_id=2),  # 4
            MultWire(is_output=True, wire_a_id=3, wire_b_id=4),  # 5
        ],
        "deep": [
            InputWire(is_output=False, owner_id=0),  # 0
            InputWire(is_output=False, owner_id=1),  # 1
            InputWire(is_output=False, owner_id=2),  # 2
            InputWire(is_output=False, owner_id=2),  # 3
            AddWire(is_output=False, wire_a_id=0, wire_b_id=1),  # 4
            MultWire(is_output=False, wire_a_id=4, wire_b_id=2),  # 5
            AddWire(is_output=False, wire_a_id=1, wire_b_id=5),  # 6
            ConstMultWire(is_output=False, c=4, wire_a_id=6),  # 7
            AddWire(is_output=False, wire_a_id=2, wire_b_id=7),  # 8
            AddWire(is_output=False, wire_a_id=7, wire_b_id=8),  # 9
            MultWire(is_output=False, wire_a_id=4, wire_b_id=9),  # 10
            MultWire(is_output=True, wire_a_id=3, wire_b_id=10),  # 11
        ],
        "wide": [
            InputWire(is_output=False, owner_id=0),  # 0
            InputWire(is_output=False, owner_id=0),  # 1
            InputWire(is_output=False, owner_id=0),  # 2
            InputWire(is_output=False, owner_id=0),  # 3
            InputWire(is_output=False, owner_id=1),  # 4
            InputWire(is_output=False, owner_id=1),  # 5
            InputWire(is_output=False, owner_id=1),  # 6
            InputWire(is_output=False, owner_id=1),  # 7
            InputWire(is_output=False, owner_id=2),  # 8
            InputWire(is_output=False, owner_id=2),  # 9
            InputWire(is_output=False, owner_id=2),  # 10
            InputWire(is_output=False, owner_id=2),  # 11
            AddWire(is_output=False, wire_a_id=0, wire_b_id=6),  # 12
            AddWire(is_output=False, wire_a_id=1, wire_b_id=7),  # 13
            AddWire(is_output=False, wire_a_id=2, wire_b_id=8),  # 14
            AddWire(is_output=False, wire_a_id=3, wire_b_id=9),  # 15
            AddWire(is_output=False, wire_a_id=4, wire_b_id=10),  # 16
            AddWire(is_output=False, wire_a_id=5, wire_b_id=11),  # 17
            MultWire(is_output=True, wire_a_id=12, wire_b_id=15),  # 18
            MultWire(is_output=True, wire_a_id=13, wire_b_id=16),  # 19
            MultWire(is_output=True, wire_a_id=14, wire_b_id=17),  # 20
        ],
        "adder": [
            InputWire(is_output=False, owner_id=0),  # 0
            InputWire(is_output=False, owner_id=1),  # 1
            InputWire(is_output=False, owner_id=2),  # 2
            AddWire(is_output=False, wire_a_id=0, wire_b_id=1),  # 3
            AddWire(is_output=True, wire_a_id=3, wire_b_id=2),  # 4
        ],
        "xors": [
            InputWire(is_output=False, owner_id=0),  # 0
            InputWire(is_output=False, owner_id=0),  # 1
            InputWire(is_output=False, owner_id=1),  # 2
            InputWire(is_output=False, owner_id=1),  # 3
            InputWire(is_output=False, owner_id=2),  # 4
            InputWire(is_output=False, owner_id=2),  # 5
            # "Gate 6"
            AddWire(is_output=False, wire_a_id=0, wire_b_id=3),  # 6
            MultWire(is_output=False, wire_a_id=0, wire_b_id=3),  # 7
            ConstMultWire(is_output=False, c=-2, wire_a_id=7),  # 8
            AddWire(is_output=True, wire_a_id=6, wire_b_id=8),  # 9
            # "Gate 7"
            AddWire(is_output=False, wire_a_id=1, wire_b_id=4),  # 10
            MultWire(is_output=False, wire_a_id=1, wire_b_id=4),  # 11
            ConstMultWire(is_output=False, c=-2, wire_a_id=11),  # 12
            AddWire(is_output=True, wire_a_id=10, wire_b_id=12),  # 13
            # "Gate 8"
            AddWire(is_output=False, wire_a_id=2, wire_b_id=5),  # 14
            MultWire(is_output=False, wire_a_id=2, wire_b_id=5),  # 15
            ConstMultWire(is_output=False, c=-2, wire_a_id=15),  # 16
            AddWire(is_output=True, wire_a_id=14, wire_b_id=16),  # 17
            # "Gate 9"
            AddWire(is_output=False, wire_a_id=3, wire_b_id=9),  # 18
            MultWire(is_output=False, wire_a_id=3, wire_b_id=9),  # 19
            ConstMultWire(is_output=False, c=-2, wire_a_id=19),  # 20
            AddWire(is_output=True, wire_a_id=18, wire_b_id=20),  # 21
            # "Gate 10"
            AddWire(is_output=False, wire_a_id=4, wire_b_id=13),  # 22
            MultWire(is_output=False, wire_a_id=4, wire_b_id=13),  # 23
            ConstMultWire(is_output=False, c=-2, wire_a_id=23),  # 24
            AddWire(is_output=True, wire_a_id=22, wire_b_id=24),  # 25
            # "Gate 11"
            AddWire(is_output=False, wire_a_id=5, wire_b_id=17),  # 26
            MultWire(is_output=False, wire_a_id=5, wire_b_id=17),  # 27
            ConstMultWire(is_output=False, c=-2, wire_a_id=27),  # 28
            AddWire(is_output=True, wire_a_id=26, wire_b_id=28),  # 29
            # "Gate 12"
            AddWire(is_output=False, wire_a_id=9, wire_b_id=21),  # 30
            MultWire(is_output=False, wire_a_id=9, wire_b_id=21),  # 31
            ConstMultWire(is_output=False, c=-2, wire_a_id=31),  # 32
            AddWire(is_output=True, wire_a_id=30, wire_b_id=32),  # 33
            # "Gate 13"
            AddWire(is_output=False, wire_a_id=13, wire_b_id=25),  # 34
            MultWire(is_output=False, wire_a_id=13, wire_b_id=25),  # 35
            ConstMultWire(is_output=False, c=-2, wire_a_id=35),  # 36
            AddWire(is_output=True, wire_a_id=34, wire_b_id=36),  # 37
            # "Gate 14"
            AddWire(is_output=False, wire_a_id=29, wire_b_id=33),  # 38
            MultWire(is_output=False, wire_a_id=29, wire_b_id=33),  # 39
            ConstMultWire(is_output=False, c=-2, wire_a_id=39),  # 40
            AddWire(is_output=True, wire_a_id=38, wire_b_id=40),  # 41
            # "Gate 15"
            AddWire(is_output=False, wire_a_id=41, wire_b_id=37),  # 42
            MultWire(is_output=False, wire_a_id=41, wire_b_id=37),  # 43
            ConstMultWire(is_output=False, c=-2, wire_a_id=43),  # 44
            AddWire(is_output=True, wire_a_id=42, wire_b_id=44),  # 45
        ]
    }

    circuit = circuits["basic"]
    mod = 1024
    rng = SystemRandom(0)

    ttp = TTP(3, mod, rng)
    clients = [
        Client(0, ttp, circuit, {0: 9}, mod, rng),
        Client(1, ttp, circuit, {1: 5}, mod, rng),
        Client(2, ttp, circuit, {2: 3}, mod, rng)
    ]

    print(BGW.run_circuit(clients, mod))


if __name__ == "__main__":
    main()
