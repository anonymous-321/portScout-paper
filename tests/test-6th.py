import random

def generate_random_values():
    ppi = random.uniform(-10.0, 10.0)
    spd = random.uniform(-10.0, 10.0)
    return ppi, spd

def check_area(ppi, spd):
    if ppi >= 4.0 and spd >= 4.0:
        return "Red area"
    elif ppi <= -4.0 and spd >= 4.0:
        return "Green area"
    elif ppi >= 4.0 and spd <= 2.0:
        return "Yellow area"
    return "Undefined area"

# Generate random values and check areas 100 times
for _ in range(100):
    ppi, spd = generate_random_values()
    area = check_area(ppi, spd)
    print(f"PPI: {ppi:.4f}, SPD: {spd:.4f}, Area: {area}")
