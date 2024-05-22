#!/usr/bin/env python3

import angr
import claripy

def main():
    n = 1
    while True:
        proj = angr.Project('./tunnel')

# symbolic variable for the input character
        input_char = claripy.BVS('input_char', 8*n)

        initial_state = proj.factory.entry_state(stdin=input_char)

# add constraint for each character in the input
        for i in range(n):
            initial_state.solver.add(
                claripy.Or(
                input_char.get_byte(i) == ord('L'),
                input_char.get_byte(i) == ord('R'),
                input_char.get_byte(i) == ord('F'),
                input_char.get_byte(i) == ord('B'),
                input_char.get_byte(i) == ord('U'),
                input_char.get_byte(i) == ord('D'),
                input_char.get_byte(i) == ord('Q')
                )
            )

        sm = proj.factory.simulation_manager(initial_state)

# specify the address of the desired state
        desired_state_addr = 0x0000157c  # replace with the actual address
        sm.explore(find=desired_state_addr)

        if len(sm.found) > 0:
            found_state = sm.found[0]
            solution = found_state.solver.eval(input_char, cast_to=bytes)
            print(f'Solution: {solution}')
            break
        else:
            n += 1
            print(f'No solution found - n = {n}')

if __name__ == '__main__':
  main()
