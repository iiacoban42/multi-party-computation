from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
import random
from typing import Callable, Dict, List
from cryptography.fernet import Fernet

@dataclass
class Wire(ABC):
    """Any kind of wire in the circuit."""

    is_output: bool
    """`True` if and only if the value of this wire should be made public after executing the circuit."""


@dataclass
class InputWire(Wire):
    """A wire that corresponds to a client's input."""

    alice_is_owner: bool
    """`True` if and only if Alice (the garbler) is the owner of this input data."""


@dataclass
class GateWire(Wire):
    """The output wire of a gate that operates on inputs `X` and `Y` and outputs a value according to [gate]."""

    input_x_id: int
    """The wire corresponding to input `X`, as identified by that wire's index in the list of wires (i.e. circuit) that
    this wire is part of."""

    input_y_id: int
    """The wire corresponding to input `Y`, as identified by that wire's index in the list of wires (i.e. circuit) that
    this wire is part of."""

    gate: Callable[[bool, bool], bool]
    """Determines the output of this gate given the inputs."""


@dataclass
class GarbledGateWire(Wire):
    """The garbled output wire of a gate that operates on inputs `X` and `Y` and outputs a value as encoded by the
    garbled [keys]."""

    input_x_id: int
    """The wire corresponding to input `X`, as identified by that wire's index in the list of wires (i.e. circuit) that
    this wire is part of."""

    input_y_id: int
    """The wire corresponding to input `Y`, as identified by that wire's index in the list of wires (i.e. circuit) that
    this wire is part of."""

    keys: List[bytes]
    """The list of keys for the outputs of this wire."""


class Alice:
    """Alice, the client who garbles the circuit."""

    def __init__(self, circuit: List[Wire], inputs: Dict[int, bool]):
        """Initializes Alice with knowledge of the [circuit] and her own private [inputs]."""

        self.circuit = circuit
        self.inputs = inputs
        self.keys = {}
        self.garbled_circuit = []

    def generate_wire_keys(self):
        """Generates a pair of keys for each wire in the circuit, one representing `True` and the other representing
        `False`."""

        for wire in range(len(self.circuit)):
            self.keys[wire] = [Fernet.generate_key(), Fernet.generate_key()]

    def _encrypt_output_keys(self, wire, wire_id) -> List[bytes]:
        wire_x = wire.input_x_id
        wire_y = wire.input_y_id

        x_0 =  Fernet(self.keys[wire_x][0])
        x_1 =  Fernet(self.keys[wire_x][1])
        y_0 =  Fernet(self.keys[wire_y][0])
        y_1 =  Fernet(self.keys[wire_y][1])

        z_00 = self.keys[wire_id][int(wire.gate(False, False))]
        z_01 = self.keys[wire_id][int(wire.gate(False, True))]
        z_10 = self.keys[wire_id][int(wire.gate(True, False))]
        z_11 = self.keys[wire_id][int(wire.gate(True, True))]

        z_00 = y_0.encrypt(x_0.encrypt(z_00))
        z_01 = y_1.encrypt(x_0.encrypt(z_01))
        z_10 = y_0.encrypt(x_1.encrypt(z_10))
        z_11 = y_1.encrypt(x_1.encrypt(z_11))

        for i in range(8):
            print("AES encrypt")
        output_keys = [z_00, z_01, z_10, z_11]

        random.shuffle(output_keys)

        return output_keys


    def generate_garbled_circuit(self):
        """Generates the garbled circuit. In a garbled circuit, the [InputWire]s are the same, but each [GateWire] is
        replaced by a [GarbledGateWire]."""

        for wire_id, wire in enumerate(self.circuit):
            if isinstance(wire, InputWire):
                self.garbled_circuit.append(wire)
            else:
                output_keys = self._encrypt_output_keys(wire, wire_id)
                self.garbled_circuit.append(GarbledGateWire(wire.is_output,
                                                            wire.input_x_id,
                                                            wire.input_y_id,
                                                            output_keys
                                                            )
                                            )

    def get_alice_input_key(self, wire_id: int) -> bytes:
        """Returns the key corresponding to Alice's input at wire [wire_id]."""

        bit_value = self.inputs[wire_id]
        return self.keys[wire_id][int(bit_value)]


    def get_bob_input_key(self, wire_id: int, bobs_private_value: bool) -> bytes:
        """Runs oblivious transfer to allow Bob to retrieve the key for wire [wire_id] for Bob's private value
        [bobs_private_value]. For simplicity, you may assume that Alice is super duper honest and will definitely not
        remember the fact that Bob sent his private value to her. So you can just return the correct key here directly
        without any cryptography going on."""

        print("OT")

        return self.keys[wire_id][int(bobs_private_value)]

    def get_output(self, wire_id: int, key: bytes) -> bool:
        """Returns the output bit corresponding to wire [wire_id] given that Bob found [key] for this wire. Alice should
         validate that this request is sensible, but may assume that Bob is honest-but-curious."""
        if self.keys[wire_id][0] == key:
            return False
        elif self.keys[wire_id][1] == key:
            return True

class Bob:
    """Bob, the client who evaluates the garbled circuit."""

    def __init__(self, alice: Alice, inputs: Dict[int, bool]):
        """Initializes Bob with knowledge of [Alice] and his own private [inputs]."""
        self.alice = alice
        self.bob_inputs = inputs
        self.bob_keys = {}
        self.alice_keys = {}
        self.output = {}

    def get_setup_info(self):
        """Retrieves the following information from Alice: the garbled circuit, Alice's input keys, and Bob's input
        keys."""
        self.circuit = self.alice.garbled_circuit
        for wire_id, wire in enumerate(self.circuit):
            if isinstance(wire, InputWire):
                if wire.alice_is_owner:
                    self.alice_keys[wire_id] = self.alice.get_alice_input_key(wire_id)
                else:
                    bit_val = self.bob_inputs[wire_id]
                    self.bob_keys[wire_id] = self.alice.get_bob_input_key(wire_id, bit_val)

    def _decrypt_output_keys(self, x_key, y_key, encrypted_keys):

        x_key =  Fernet(x_key)
        y_key =  Fernet(y_key)
        key = None
        for i in range(4):
            print("AES decrypt")
            try:
                key = x_key.decrypt(y_key.decrypt(encrypted_keys[i]))
            except:
                pass

        return key

    def evaluate(self):
        """Evaluates the garbled circuit retrieved from Alice. At the end of this method, Bob knows exactly which output
        keys belong to which wire, but has not learnt more about whether they correspond to `True` or `False`."""
        self.output_keys = {}
        for wire_id, wire in enumerate(self.circuit):
            if isinstance(wire, GarbledGateWire):
                wire_x = wire.input_x_id
                wire_y = wire.input_y_id

                x_key = self.output_keys[wire_x]
                y_key = self.output_keys[wire_y]
                self.output_keys[wire_id] = self._decrypt_output_keys(x_key, y_key, wire.keys)
            else:
                if wire_id in self.alice_keys:
                    self.output_keys[wire_id] = self.alice_keys[wire_id]
                else:
                    self.output_keys[wire_id] = self.bob_keys[wire_id]

    def retrieve_outputs(self) -> Dict[int, bool]:
        """Determines the semantic meaning of the keys that Bob obtained in [evaluate] for the output wires by
        interacting with Alice."""
        for wire_id, wire in enumerate(self.circuit):
            if wire.is_output:
                self.output[wire_id] = self.alice.get_output(wire_id, self.output_keys[wire_id])
        return self.output

def run_garbled_circuit(alice: Alice, bob: Bob) -> Dict[int, bool]:
    """Evaluates the garbled circuit through Alice and Bob and returns the outputs."""
    alice.generate_wire_keys()
    alice.generate_garbled_circuit()
    bob.get_setup_info()
    bob.evaluate()
    return bob.retrieve_outputs()


def main():
    gates = {
        "and": lambda x, y: x and y,
        "or": lambda x, y: x or y,
        "xor": lambda x, y: x != y,
        "if": lambda x, y: x <= y,
        "iff": lambda x, y: x == y,
        "not-x": lambda x, y: not x,
        "not-y": lambda x, y: not y,
    }

    circuits = {
        "basic": [
            InputWire(is_output=False, alice_is_owner=True),  # 0
            InputWire(is_output=False, alice_is_owner=True),  # 1
            InputWire(is_output=False, alice_is_owner=False),  # 2
            InputWire(is_output=False, alice_is_owner=False),  # 3
            GateWire(is_output=False, input_x_id=0, input_y_id=1, gate=gates["or"]),  # 4
            GateWire(is_output=False, input_x_id=2, input_y_id=3, gate=gates["or"]),  # 5
            GateWire(is_output=True, input_x_id=4, input_y_id=5, gate=gates["and"]),  # 6
        ],
        "deep": [
            InputWire(is_output=False, alice_is_owner=True),  # 0
            InputWire(is_output=False, alice_is_owner=True),  # 1
            InputWire(is_output=False, alice_is_owner=False),  # 2
            InputWire(is_output=False, alice_is_owner=False),  # 3
            GateWire(is_output=False, input_x_id=0, input_y_id=1, gate=gates["or"]),  # 4
            GateWire(is_output=False, input_x_id=4, input_y_id=2, gate=gates["and"]),  # 5
            GateWire(is_output=False, input_x_id=1, input_y_id=5, gate=gates["xor"]),  # 6
            GateWire(is_output=False, input_x_id=6, input_y_id=0, gate=gates["not-x"]),  # 7
            GateWire(is_output=False, input_x_id=2, input_y_id=7, gate=gates["or"]),  # 8
            GateWire(is_output=False, input_x_id=7, input_y_id=8, gate=gates["if"]),  # 9
            GateWire(is_output=False, input_x_id=4, input_y_id=9, gate=gates["and"]),  # 10
            GateWire(is_output=True, input_x_id=3, input_y_id=10, gate=gates["iff"]),  # 11
        ],
        "wide": [
            InputWire(is_output=False, alice_is_owner=True),  # 0
            InputWire(is_output=False, alice_is_owner=True),  # 1
            InputWire(is_output=False, alice_is_owner=True),  # 2
            InputWire(is_output=False, alice_is_owner=True),  # 3
            InputWire(is_output=False, alice_is_owner=True),  # 4
            InputWire(is_output=False, alice_is_owner=True),  # 5
            InputWire(is_output=False, alice_is_owner=False),  # 6
            InputWire(is_output=False, alice_is_owner=False),  # 7
            InputWire(is_output=False, alice_is_owner=False),  # 8
            InputWire(is_output=False, alice_is_owner=False),  # 9
            InputWire(is_output=False, alice_is_owner=False),  # 10
            InputWire(is_output=False, alice_is_owner=False),  # 11
            GateWire(is_output=False, input_x_id=0, input_y_id=6, gate=gates["or"]),  # 12
            GateWire(is_output=False, input_x_id=1, input_y_id=7, gate=gates["or"]),  # 13
            GateWire(is_output=False, input_x_id=2, input_y_id=8, gate=gates["or"]),  # 14
            GateWire(is_output=False, input_x_id=3, input_y_id=9, gate=gates["or"]),  # 15
            GateWire(is_output=False, input_x_id=4, input_y_id=10, gate=gates["or"]),  # 16
            GateWire(is_output=False, input_x_id=5, input_y_id=11, gate=gates["or"]),  # 17
            GateWire(is_output=True, input_x_id=12, input_y_id=15, gate=gates["and"]),  # 18
            GateWire(is_output=True, input_x_id=13, input_y_id=16, gate=gates["and"]),  # 19
            GateWire(is_output=True, input_x_id=14, input_y_id=17, gate=gates["and"]),  # 20
        ],
        "adder": [
            # Alice's input
            InputWire(is_output=False, alice_is_owner=True),  # 0
            InputWire(is_output=False, alice_is_owner=True),  # 1
            InputWire(is_output=False, alice_is_owner=True),  # 2
            InputWire(is_output=False, alice_is_owner=True),  # 3
            # Bob's input
            InputWire(is_output=False, alice_is_owner=False),  # 4
            InputWire(is_output=False, alice_is_owner=False),  # 5
            InputWire(is_output=False, alice_is_owner=False),  # 6
            InputWire(is_output=False, alice_is_owner=False),  # 7
            # Half adder 1
            GateWire(is_output=True, input_x_id=0, input_y_id=4, gate=gates["xor"]),  # 8
            GateWire(is_output=False, input_x_id=0, input_y_id=4, gate=gates["and"]),  # 9
            # Full adder 2
            GateWire(is_output=False, input_x_id=1, input_y_id=5, gate=gates["xor"]),  # 10
            GateWire(is_output=True, input_x_id=10, input_y_id=9, gate=gates["xor"]),  # 11
            GateWire(is_output=False, input_x_id=1, input_y_id=5, gate=gates["and"]),  # 12
            GateWire(is_output=False, input_x_id=9, input_y_id=10, gate=gates["and"]),  # 13
            GateWire(is_output=False, input_x_id=12, input_y_id=13, gate=gates["or"]),  # 14
            # Full adder 3
            GateWire(is_output=False, input_x_id=2, input_y_id=6, gate=gates["xor"]),  # 15
            GateWire(is_output=True, input_x_id=15, input_y_id=14, gate=gates["xor"]),  # 16
            GateWire(is_output=False, input_x_id=2, input_y_id=6, gate=gates["and"]),  # 17
            GateWire(is_output=False, input_x_id=14, input_y_id=15, gate=gates["and"]),  # 18
            GateWire(is_output=False, input_x_id=17, input_y_id=18, gate=gates["or"]),  # 19
            # Full adder 4
            GateWire(is_output=False, input_x_id=3, input_y_id=7, gate=gates["xor"]),  # 20
            GateWire(is_output=True, input_x_id=20, input_y_id=19, gate=gates["xor"]),  # 21
            GateWire(is_output=False, input_x_id=3, input_y_id=7, gate=gates["and"]),  # 22
            GateWire(is_output=False, input_x_id=19, input_y_id=20, gate=gates["and"]),  # 23
            GateWire(is_output=True, input_x_id=22, input_y_id=23, gate=gates["or"]),  # 24
        ],
        "xors": [
            InputWire(is_output=False, alice_is_owner=True),  # 0
            InputWire(is_output=False, alice_is_owner=True),  # 1
            InputWire(is_output=False, alice_is_owner=True),  # 2
            InputWire(is_output=False, alice_is_owner=False),  # 3
            InputWire(is_output=False, alice_is_owner=False),  # 4
            InputWire(is_output=False, alice_is_owner=False),  # 5
            GateWire(is_output=False, input_x_id=0, input_y_id=3, gate=gates["xor"]),  # 6
            GateWire(is_output=False, input_x_id=1, input_y_id=4, gate=gates["xor"]),  # 7
            GateWire(is_output=False, input_x_id=2, input_y_id=5, gate=gates["xor"]),  # 8
            GateWire(is_output=False, input_x_id=3, input_y_id=6, gate=gates["xor"]),  # 9
            GateWire(is_output=False, input_x_id=4, input_y_id=7, gate=gates["xor"]),  # 10
            GateWire(is_output=False, input_x_id=5, input_y_id=8, gate=gates["xor"]),  # 11
            GateWire(is_output=False, input_x_id=6, input_y_id=9, gate=gates["xor"]),  # 12
            GateWire(is_output=False, input_x_id=7, input_y_id=10, gate=gates["xor"]),  # 13
            GateWire(is_output=False, input_x_id=11, input_y_id=12, gate=gates["xor"]),  # 14
            GateWire(is_output=True, input_x_id=14, input_y_id=13, gate=gates["xor"]),  # 15
        ]
    }

    alice = Alice(circuits["basic"], {0: True, 1: False})
    bob = Bob(alice, {2: False, 3: True})

    print(f"basic {run_garbled_circuit(alice, bob)}")


    alice = Alice(circuits["deep"], {0: True, 1: False})
    bob = Bob(alice, {2: False, 3: True})

    print(f"deep {run_garbled_circuit(alice, bob)}")


    alice = Alice(circuits["wide"], {0: True, 1: False, 2: True, 3: False, 4: True, 5: True})
    bob = Bob(alice, {6: False, 7: True, 8: False, 9: True, 10: False, 11: True})

    print(f"wide {run_garbled_circuit(alice, bob)}")


    alice = Alice(circuits["adder"], {0: True, 1: False, 2: True, 3: False})
    bob = Bob(alice, { 4: True, 5: True, 6: False, 7: True})

    print(f"adder {run_garbled_circuit(alice, bob)}")

    alice = Alice(circuits["xors"], {0: True, 1: False, 2:True})
    bob = Bob(alice, {3: False, 4: True, 5: False})

    print(f"xors {run_garbled_circuit(alice, bob)}")

if __name__ == "__main__":
    main()
