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
        raise Exception("Not implemented.")

    @staticmethod
    def recover_secret(shares: List[int], mod: int) -> int:
        """Reconstructs the secret that the additive secret [shares] make up under modulo [mod]."""
        raise Exception("Not implemented.")

    @staticmethod
    def add(a_share: int, b_share: int, mod: int) -> int:
        """Adds the shares [a_share] and [b_share] together under modulo [mod]."""
        raise Exception("Not implemented.")

    @staticmethod
    def const_mult(c: int, a_share: int, mod: int) -> int:
        """Multiplies the share [a_share] with the constant [c] under modulo [mod]."""
        raise Exception("Not implemented.")

    @staticmethod
    def mult(is_alice: bool, x_share: int, y_share: int, z_share: int, a_prime: int, b_prime: int, mod: int) -> int:
        """Performs the masked multiplication corresponding to `A * B` using the formula from the slides, under modulo
        [mod]. The constant term is added only if [is_alice] is `True`."""
        raise Exception("Not implemented.")

    @staticmethod
    def run_circuit(clients: List[Client]) -> Dict[int, int]:
        """Makes the [clients] interactively compute their circuit by synchronously invoking their methods, and returns
        all outputs of the circuit."""
        raise Exception("Not implemented.")


class TTP:
    """A trusted third party that can be trusted to generate Beaver triples."""

    def __init__(self, client_count: int, mod: int, rng: SystemRandom):
        """Initializes this [TTP], given the number of clients [client_count] participating in the protocol, the modulo
        [mod] to perform secret sharing under, and a source of randomness [rng]."""
        raise Exception("Not implemented.")

    def get_beaver_triple(self, gate_id: int, client_id: int) -> [int, int, int]:
        """Returns shares of the Beaver triple for multiplication gate [gate_id] for [client_id]. Make sure that clients
        requesting shares for the same [gate_id] actually get shares of the same Beaver triple."""
        raise Exception("Not implemented.")


class Client:
    """A client in the BGW protocol."""

    def __init__(self, client_id: int, ttp: TTP, circuit: List[Wire], inputs: Dict[int, int], mod: int,
                 rng: SystemRandom):
        """Constructs a new [Client], but does not do any significant computation yet. Here, [client_id] uniquely
        identifies this client, [ttp] is the TTP that will provide the client with shares of Beaver triples, [circuit]
        is the circuit that will be executed, [inputs] is a mapping from wire indices to this client's private input
        values, [mod] is the modulo under which the circuit is computed, and [rng] is the source of randomness used
        whenever possible."""
        raise Exception("Not implemented.")

    def set_clients(self, clients: List[Client]):
        """Gives this client knowledge of the [Client]s that participate in the protocol."""
        raise Exception("Not implemented.")

    def get_input_share(self, wire_id: int, requester_id: int) -> int:
        """Returns the share of this client's input at wire [wire_id] that they created for client [requester_id]. This
        client should validate that this request is sensible, but may assume that the requester is
        honest-but-curious."""
        raise Exception("Not implemented.")

    def get_masked_shares(self, wire_id: int) -> [int, int]:
        """Returns the masked shares `A - X` and `B - Y` that this client created for the multiplication at wire
        [wire_id]."""
        raise Exception("Not implemented.")

    def get_output_share(self, wire_id: int) -> int:
        """Returns the share that this client calculated for the wire [wire_id], to be used to reconstruct the value of
        this wire. This client should validate that this request is sensible, but may assume that the requester is
        honest-but-curious."""
        raise Exception("Not implemented.")

    def local_setup(self):
        """Performs the local part of the setup, which consists of creating shares for this client's inputs."""
        raise Exception("Not implemented.")

    def interactive_setup(self):
        """Performs the interactive part of the setup, which consist of retrieving shares of Beaver triples from the
        TTP and fetching the shares that other clients have created of their inputs for this client."""
        raise Exception("Not implemented.")

    def run_circuit_until_mult(self, start_at_wire_id: int) -> int | None:
        """Runs the circuit starting at wire [start_at_wire_id] until it encounters a multiplication gate. If a
        multiplication gate is encountered, this client performs some local computation, and then returns the id of the
        wire it stopped at. This client may assume that the next time this method is invoked, it continues at the
        multiplication it left off at by performing the interactive part of the multiplication. After that, this client
        continues to run the circuit until it encounters another multiplication gate. If this client is done with the
        circuit, this function returns `None`."""
        raise Exception("Not implemented.")

    def get_outputs(self) -> Dict[int, int]:
        """Returns a dictionary from wire IDs to the reconstructed outputs at those wires, corresponding to all outputs
        of the circuit."""
        raise Exception("Not implemented.")


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

    print(BGW.run_circuit(clients))


if __name__ == "__main__":
    main()
