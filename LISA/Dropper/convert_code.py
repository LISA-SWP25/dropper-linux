AGENT_FILE_PATH = "agent.elf"
OUTPUT_PY_FILE = "agent_payload_embed.py"

with open(AGENT_FILE_PATH, "rb") as f:
    binary_data = f.read()

hex_lines = []
line = b''
for i, byte in enumerate(binary_data):
    line += b'\\x%02x' % byte
    if (i + 1) % 16 == 0:
        hex_lines.append(f'b"{line.decode()}"')
        line = b''
if line:
    hex_lines.append(f'b"{line.decode()}"')

with open(OUTPUT_PY_FILE, "w") as f:
    f.write("EMBEDDED_PAYLOAD = (\n")
    for l in hex_lines:
        f.write(f"    {l}\n")
    f.write(")\n")
