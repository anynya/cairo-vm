#!/bin/bash

# Define the path to the Cairo programs directory
PROGRAMS_DIR="../cairo_programs/cairo-1-programs/"

# List of Cairo program names
PROGRAMS=(
    "array_append.cairo"
    "array_get.cairo"
    "array_integer_tuple.cairo"
    "bytes31_ret.cairo"
    "dict_with_struct.cairo"
    "dictionaries.cairo"
    "enum_flow.cairo"
    "enum_match.cairo"
    "factorial.cairo"
    "felt_dict.cairo"
    "felt_dict_squash.cairo"
    "felt_span.cairo"
    "fibonacci.cairo"
    "hello.cairo"
    "null_ret.cairo"
    "nullable_box_vec.cairo"
    "nullable_dict.cairo"
    "ops.cairo"
    "pedersen_example.cairo"
    "poseidon.cairo"
    "poseidon_pedersen.cairo"
    "print.cairo"
    "recursion.cairo"
    "sample.cairo"
    "simple.cairo"
    "simple_struct.cairo"
    "struct_span_return.cairo"
    "tensor_new.cairo"
)

# Loop through each program and execute the command
for program in "${PROGRAMS[@]}"; do
    echo "Running $program..."
    cargo run "$PROGRAMS_DIR$program" --layout small --proof_mode
done

