import math
import os
import time


def build_sans_model():
  step = 0.75
  coords = [i * step for i in range(-15, 16)]
  voxels = {}

  for x in coords:
    for y in coords:
      for z in coords:
        # 1. Базовая форма черепа: верхний свод, широкие скулы и подбородок
        cranium = (x / 9.6) ** 2 + ((y - 2.2) / 8.0) ** 2 + (z / 8.8) ** 2 <= 1.0
        cheeks = (
            ((abs(x) - 4.5) / 6.0) ** 2
            + ((y + 2.0) / 4.3) ** 2
            + ((z - 0.8) / 7.2) ** 2
            <= 1.0
        )
        jaw = (x / 7.5) ** 2 + ((y + 4.4) / 4.1) ** 2 + ((z - 0.6) / 6.6) ** 2 <= 1.0

        solid = cranium or cheeks or jaw

        # 2. Вырезаем черты лица на передней части черепа
        if solid and z > 3.2:
          # Глазницы
          in_eye_socket = (
              ((abs(x) - 4.1) / 2.65) ** 2 + ((y - 1.3) / 2.55) ** 2 <= 1.0
          )
          if in_eye_socket and z > 4.0:
            solid = False

          # Носовая полость (перевёрнутый треугольник)
          if -2.1 <= y <= -0.1 and abs(x) <= (-0.1 - y) * 0.75 and z > 4.6:
            solid = False

          # Широкая улыбка и зубы
          smile_y = -4.7 + 0.032 * (x**2)
          if abs(x) <= 7.2 and abs(y - smile_y) <= 1.15 and z > 4.6:
            is_tooth = (
                abs(x) <= 0.45
                or 2.1 <= abs(x) <= 2.75
                or 4.3 <= abs(x) <= 4.95
                or 6.4 <= abs(x) <= 7.1
            )
            if not is_tooth:
              solid = False

        if solid:
          # Помечаем внутреннюю глубину рта и глазниц как тёмную полость
          is_cavity = z > 3.2 and (
              (((abs(x) - 4.1) / 2.7) ** 2 + ((y - 1.3) / 2.6) ** 2 <= 1.0 and z <= 4.3)
              or (
                  abs(x) <= 7.2
                  and abs(y - (-4.7 + 0.032 * (x**2))) <= 1.15
                  and z <= 4.9
              )
          )
          voxels[(x, y, z)] = "cavity" if is_cavity else "bone"

        # 3. Светящийся левый глаз Санса (справа от зрителя при взгляде анфас)
        if (x - 4.1) ** 2 + (y - 1.3) ** 2 + (z - 4.7) ** 2 <= 1.35**2:
          voxels[(x, y, z)] = "eye"

  # Оставляем только поверхностные воксели и считаем векторы нормалей для теней
  surface = []
  neighbors = [
      (dx * step, dy * step, dz * step)
      for dx in (-1, 0, 1)
      for dy in (-1, 0, 1)
      for dz in (-1, 0, 1)
      if (dx, dy, dz) != (0, 0, 0)
  ]

  for (x, y, z), kind in voxels.items():
    nx, ny, nz = 0.0, 0.0, 0.0
    exposed = False
    for dx, dy, dz in neighbors:
      if (round(x + dx, 4), round(y + dy, 4), round(z + dz, 4)) not in voxels:
        nx += dx
        ny += dy
        nz += dz
        if abs(dx) + abs(dy) + abs(dz) == step:
          exposed = True

    if exposed or kind == "eye":
      length = math.hypot(nx, ny, nz) or 1.0
      surface.append((x, y, z, nx / length, ny / length, nz / length, kind))

  return surface


def render():