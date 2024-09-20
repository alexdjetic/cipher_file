#!/bin/bash

# Name of the output file
output_file="test_message.txt"

# Clear the file if it already exists
> "$output_file"

# Function to generate a random sentence
generate_sentence() {
    local words=("The" "quick" "brown" "fox" "jumps" "over" "the" "lazy" "dog" "A" "small" "leak" "will" "sink" "a" "great" "ship" "All" "that" "glitters" "is" "not" "gold" "Actions" "speak" "louder" "than" "words")
    local sentence=""
    local length=$((RANDOM % 10 + 5))  # Random length between 5 and 14 words
    for ((i=0; i<length; i++)); do
        sentence+="${words[$RANDOM % ${#words[@]}]} "
    done
    echo "$sentence"
}

# Generate content (approximately 1MB)
for i in {1..20000}  # This will generate about 1MB of text
do
    generate_sentence >> "$output_file"
done

echo "Created a test message file: $output_file"
echo "File size: $(du -h "$output_file" | cut -f1)"