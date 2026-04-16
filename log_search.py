with open("log.txt", "r") as file:
    lines = file.readlines()

word = input("Enter word to search: ")

results = [line for line in lines if word.lower() in line.lower()]

if results:
    print(f"\nFound {len(results)} lines containing '{word}':\n")
    for line in results:
        print(line.strip())
else:
    print(f"No lines found containing '{word}'")