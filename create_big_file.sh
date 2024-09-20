#!/bin/bash

# Name of the output file
output_file="test_output.txt"

# Clear the file if it already exists
> "$output_file"

# Add "test" 150 times
for i in {1..150}
do
   echo "test" >> "$output_file"
done

echo "Added 'test' 150 times to $output_file"