//! Layout algorithms for positioning atoms in 3D space.
//!
//! Provides 4 different layout algorithms to experiment with:
//! 1. Layered Spherical - concentric shells by category hierarchy
//! 2. Force-Directed - spring physics simulation
//! 3. Hierarchical Tree - parent-child radial layout
//! 4. Spiral Galaxy - logarithmic spiral arrangement

use crate::types::Malecule;
use std::f64::consts::{PI, TAU};

/// Layout algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LayoutAlgorithm {
    /// Concentric spherical shells by hierarchy depth
    #[default]
    LayeredSpherical,
    /// Spring-based force simulation
    ForceDirected,
    /// Radial tree from center
    HierarchicalTree,
    /// Logarithmic spiral arrangement
    SpiralGalaxy,
}

/// Bond length in angstroms (standard C-C bond is ~1.54Å)
const BOND_LENGTH: f64 = 1.5;

/// Applies the selected layout algorithm to position atoms.
pub fn apply_layout(malecule: &mut Malecule, algorithm: LayoutAlgorithm) {
    match algorithm {
        LayoutAlgorithm::LayeredSpherical => layout_layered_spherical(malecule),
        LayoutAlgorithm::ForceDirected => layout_force_directed(malecule),
        LayoutAlgorithm::HierarchicalTree => layout_hierarchical_tree(malecule),
        LayoutAlgorithm::SpiralGalaxy => layout_spiral_galaxy(malecule),
    }
}

/// Layered Spherical Layout
///
/// Places atoms on concentric spheres:
/// - Layer 0: Central carbon atom at origin
/// - Layer 1: Top-level category atoms (O, B, Mg, W) on inner sphere
/// - Layer 2: Subcategory atoms on outer sphere
///
/// Uses golden angle distribution for even spacing on each sphere.
fn layout_layered_spherical(malecule: &mut Malecule) {
    if malecule.atoms.is_empty() {
        return;
    }

    // Golden angle for even distribution
    let golden_angle = PI * (3.0 - 5.0_f64.sqrt());

    // Classify atoms by layer based on category structure
    let mut layer0: Vec<usize> = Vec::new(); // Central (empty category)
    let mut layer1: Vec<usize> = Vec::new(); // Top-level (objectives, micro-behaviors, etc.)
    let mut layer2: Vec<usize> = Vec::new(); // Subcategories (objectives/lateral-movement, etc.)

    for (i, atom) in malecule.atoms.iter().enumerate() {
        if atom.category.is_empty() {
            layer0.push(i);
        } else if !atom.category.contains('/') {
            // Top-level categories like "objectives", "micro-behaviors"
            layer1.push(i);
        } else {
            // Subcategories
            layer2.push(i);
        }
    }

    // Layer 0: Origin (central carbon)
    for &idx in &layer0 {
        malecule.atoms[idx].position = (0.0, 0.0, 0.0);
    }

    // Layer 1: Inner sphere (radius = BOND_LENGTH) for hub atoms
    let radius1 = BOND_LENGTH;
    let n1 = layer1.len().max(1) as f64;
    for (i, &idx) in layer1.iter().enumerate() {
        // Distribute evenly around the center using spherical coordinates
        let theta = TAU * i as f64 / n1;
        let phi = PI / 3.0; // 60 degrees from vertical for visual appeal

        let x = radius1 * phi.sin() * theta.cos();
        let y = radius1 * phi.sin() * theta.sin();
        let z = radius1 * phi.cos();

        malecule.atoms[idx].position = (x, y, z);
    }

    // Layer 2: Outer sphere (radius = 2.5 * BOND_LENGTH) for subcategories
    let radius2 = 2.5 * BOND_LENGTH;
    let n2 = layer2.len().max(1) as f64;
    for (i, &idx) in layer2.iter().enumerate() {
        let theta = golden_angle * i as f64;
        let phi = PI * (i as f64 + 0.5) / n2;

        let x = radius2 * phi.sin() * theta.cos();
        let y = radius2 * phi.sin() * theta.sin();
        let z = radius2 * phi.cos();

        malecule.atoms[idx].position = (x, y, z);
    }
}

/// Force-Directed Layout
///
/// Uses a simplified spring-electric simulation:
/// - Bonds act as springs (attractive)
/// - All atoms repel each other (Coulomb-like)
/// - Iterates until stable
fn layout_force_directed(malecule: &mut Malecule) {
    let n = malecule.atoms.len();
    if n == 0 {
        return;
    }

    // Initial placement: random-ish positions based on index
    for (i, atom) in malecule.atoms.iter_mut().enumerate() {
        let angle = TAU * i as f64 / n.max(1) as f64;
        let radius = (i as f64 + 1.0) * 0.5;
        atom.position = (
            radius * angle.cos(),
            radius * angle.sin(),
            (i as f64 * 0.3) - (n as f64 * 0.15),
        );
    }

    // Build adjacency from bonds
    let mut neighbors: Vec<Vec<usize>> = vec![Vec::new(); n];
    for bond in &malecule.bonds {
        neighbors[bond.atom1].push(bond.atom2);
        neighbors[bond.atom2].push(bond.atom1);
    }

    // Simulation parameters - use half bond length for more compact layout
    let ideal_length = BOND_LENGTH * 0.5;
    let repulsion = 1.0;
    let attraction = 0.1;
    let damping = 0.9;
    let iterations = 100;

    let mut velocities: Vec<(f64, f64, f64)> = vec![(0.0, 0.0, 0.0); n];

    for _ in 0..iterations {
        let mut forces: Vec<(f64, f64, f64)> = vec![(0.0, 0.0, 0.0); n];

        // Repulsion between all pairs
        for i in 0..n {
            for j in (i + 1)..n {
                let (dx, dy, dz) = sub(malecule.atoms[j].position, malecule.atoms[i].position);
                let dist = (dx * dx + dy * dy + dz * dz).sqrt().max(0.1);
                let force = repulsion / (dist * dist);

                let fx = force * dx / dist;
                let fy = force * dy / dist;
                let fz = force * dz / dist;

                forces[i] = sub(forces[i], (fx, fy, fz));
                forces[j] = add(forces[j], (fx, fy, fz));
            }
        }

        // Attraction along bonds
        for i in 0..n {
            for &j in &neighbors[i] {
                if j > i {
                    continue;
                }
                let (dx, dy, dz) = sub(malecule.atoms[j].position, malecule.atoms[i].position);
                let dist = (dx * dx + dy * dy + dz * dz).sqrt().max(0.1);
                let force = attraction * (dist - ideal_length);

                let fx = force * dx / dist;
                let fy = force * dy / dist;
                let fz = force * dz / dist;

                forces[i] = add(forces[i], (fx, fy, fz));
                forces[j] = sub(forces[j], (fx, fy, fz));
            }
        }

        // Apply forces
        for i in 0..n {
            velocities[i] = add(scale(velocities[i], damping), forces[i]);
            malecule.atoms[i].position = add(malecule.atoms[i].position, velocities[i]);
        }
    }

    // Center the molecule
    center_molecule(malecule);
}

/// Hierarchical Tree Layout
///
/// Arranges atoms in a radial tree structure:
/// - Central atom at origin
/// - Children arranged in a cone around parent
/// - Uses bond relationships to determine hierarchy
fn layout_hierarchical_tree(malecule: &mut Malecule) {
    let n = malecule.atoms.len();
    if n == 0 {
        return;
    }

    // Build parent-child relationships from bonds
    // First atom (usually C) is root
    let mut parent: Vec<Option<usize>> = vec![None; n];
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];

    // BFS from atom 0 to build tree
    let mut visited = vec![false; n];
    let mut queue = vec![0usize];
    visited[0] = true;

    // Build adjacency from bonds
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    for bond in &malecule.bonds {
        adj[bond.atom1].push(bond.atom2);
        adj[bond.atom2].push(bond.atom1);
    }

    while let Some(current) = queue.pop() {
        for &neighbor in &adj[current] {
            if !visited[neighbor] {
                visited[neighbor] = true;
                parent[neighbor] = Some(current);
                children[current].push(neighbor);
                queue.push(neighbor);
            }
        }
    }

    // Place root at origin
    malecule.atoms[0].position = (0.0, 0.0, 0.0);

    // Recursively place children
    fn place_children(
        atoms: &mut [crate::types::Atom],
        children: &[Vec<usize>],
        parent_idx: usize,
        parent_pos: (f64, f64, f64),
        direction: (f64, f64, f64),
        _depth: usize,
    ) {
        let kids = &children[parent_idx];
        if kids.is_empty() {
            return;
        }

        let cone_angle = PI / 3.0; // 60 degree cone
        let spread = TAU / kids.len().max(1) as f64;

        for (i, &child) in kids.iter().enumerate() {
            // Rotate around parent direction
            let theta = spread * i as f64;
            let phi = cone_angle;

            // Calculate position relative to parent
            let len = BOND_LENGTH;

            // Simple cone placement
            let base_dir = if direction.2.abs() < 0.9 {
                normalize(cross(direction, (0.0, 0.0, 1.0)))
            } else {
                normalize(cross(direction, (1.0, 0.0, 0.0)))
            };

            let perp = normalize(cross(direction, base_dir));

            let offset_x = len
                * (phi.sin() * (theta.cos() * base_dir.0 + theta.sin() * perp.0)
                    + phi.cos() * direction.0);
            let offset_y = len
                * (phi.sin() * (theta.cos() * base_dir.1 + theta.sin() * perp.1)
                    + phi.cos() * direction.1);
            let offset_z = len
                * (phi.sin() * (theta.cos() * base_dir.2 + theta.sin() * perp.2)
                    + phi.cos() * direction.2);

            let child_pos = (
                parent_pos.0 + offset_x,
                parent_pos.1 + offset_y,
                parent_pos.2 + offset_z,
            );

            atoms[child].position = child_pos;

            // New direction for children
            let new_dir = normalize((offset_x, offset_y, offset_z));
            place_children(atoms, children, child, child_pos, new_dir, _depth + 1);
        }
    }

    place_children(
        &mut malecule.atoms,
        &children,
        0,
        (0.0, 0.0, 0.0),
        (0.0, 0.0, 1.0),
        0,
    );

    // Handle disconnected atoms
    let mut orphan_idx = 0;
    for (&is_visited, atom) in visited.iter().zip(malecule.atoms.iter_mut()) {
        if !is_visited {
            let angle = TAU * orphan_idx as f64 / 8.0;
            atom.position = (
                3.0 * BOND_LENGTH * angle.cos(),
                3.0 * BOND_LENGTH * angle.sin(),
                -2.0 * BOND_LENGTH,
            );
            orphan_idx += 1;
        }
    }
}

/// Spiral Galaxy Layout
///
/// Arranges atoms in a logarithmic spiral pattern:
/// - Central atom at origin
/// - Other atoms spiral outward
/// - Creates a visually appealing "galaxy" shape
fn layout_spiral_galaxy(malecule: &mut Malecule) {
    let n = malecule.atoms.len();
    if n == 0 {
        return;
    }

    // Place first atom at center
    malecule.atoms[0].position = (0.0, 0.0, 0.0);

    if n == 1 {
        return;
    }

    // Parameters for logarithmic spiral: r = a * e^(b*theta)
    let a = 0.3; // Starting radius
    let b = 0.15; // Spiral tightness
    let z_spread = 0.3; // Vertical spread

    // Sort atoms by category depth for spiral order
    let mut indices: Vec<(usize, usize)> = malecule
        .atoms
        .iter()
        .enumerate()
        .skip(1) // Skip central atom
        .map(|(i, atom)| (i, atom.category.matches('/').count()))
        .collect();

    // Sort by depth, then by index
    indices.sort_by_key(|&(i, depth)| (depth, i));

    for (spiral_idx, &(atom_idx, depth)) in indices.iter().enumerate() {
        let t = (spiral_idx + 1) as f64;
        let theta = 2.5 * t; // Angle increases faster for tighter spiral

        // Logarithmic spiral radius
        let r = a * (b * theta).exp();

        // Add some vertical displacement based on depth
        let z = (depth as f64 - 1.0) * z_spread;

        let x = r * theta.cos();
        let y = r * theta.sin();

        malecule.atoms[atom_idx].position = (x, y, z);
    }

    // Scale to reasonable bond lengths
    let max_dist = malecule
        .atoms
        .iter()
        .map(|a| {
            let (x, y, z) = a.position;
            (x * x + y * y + z * z).sqrt()
        })
        .fold(0.0_f64, f64::max);

    if max_dist > 0.0 {
        let scale = (n as f64).sqrt() * BOND_LENGTH / max_dist;
        for atom in &mut malecule.atoms {
            atom.position = scale3(atom.position, scale);
        }
    }
}

// Vector math helpers

fn add(a: (f64, f64, f64), b: (f64, f64, f64)) -> (f64, f64, f64) {
    (a.0 + b.0, a.1 + b.1, a.2 + b.2)
}

fn sub(a: (f64, f64, f64), b: (f64, f64, f64)) -> (f64, f64, f64) {
    (a.0 - b.0, a.1 - b.1, a.2 - b.2)
}

fn scale(a: (f64, f64, f64), s: f64) -> (f64, f64, f64) {
    (a.0 * s, a.1 * s, a.2 * s)
}

fn scale3(a: (f64, f64, f64), s: f64) -> (f64, f64, f64) {
    (a.0 * s, a.1 * s, a.2 * s)
}

fn cross(a: (f64, f64, f64), b: (f64, f64, f64)) -> (f64, f64, f64) {
    (
        a.1 * b.2 - a.2 * b.1,
        a.2 * b.0 - a.0 * b.2,
        a.0 * b.1 - a.1 * b.0,
    )
}

fn normalize(v: (f64, f64, f64)) -> (f64, f64, f64) {
    let len = (v.0 * v.0 + v.1 * v.1 + v.2 * v.2).sqrt();
    if len < 1e-10 {
        (0.0, 0.0, 1.0)
    } else {
        (v.0 / len, v.1 / len, v.2 / len)
    }
}

fn center_molecule(malecule: &mut Malecule) {
    if malecule.atoms.is_empty() {
        return;
    }

    let n = malecule.atoms.len() as f64;
    let (cx, cy, cz) = malecule
        .atoms
        .iter()
        .fold((0.0, 0.0, 0.0), |acc, atom| add(acc, atom.position));

    let center = (cx / n, cy / n, cz / n);

    for atom in &mut malecule.atoms {
        atom.position = sub(atom.position, center);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elements::CARBON;
    use crate::types::Severity;

    fn make_test_malecule() -> Malecule {
        let mut m = Malecule::new("test");

        // Central carbon
        m.add_atom(CARBON, "".to_string(), Severity::Neutral);

        // Top-level categories
        m.add_atom(
            crate::elements::OXYGEN,
            "objectives".to_string(),
            Severity::Neutral,
        );
        m.add_atom(
            crate::elements::HYDROGEN_MICRO,
            "micro-behaviors".to_string(),
            Severity::Neutral,
        );

        // Subcategories
        m.add_atom(
            crate::elements::LANTHANUM,
            "objectives/lateral-movement".to_string(),
            Severity::Suspicious,
        );
        m.add_atom(
            crate::elements::FLUORINE,
            "micro-behaviors/fs".to_string(),
            Severity::Notable,
        );

        // Bonds: C-O, C-B, O-La, B-F
        m.add_bond(0, 1, 1);
        m.add_bond(0, 2, 1);
        m.add_bond(1, 3, 1);
        m.add_bond(2, 4, 1);

        m
    }

    #[test]
    fn test_layered_spherical() {
        let mut m = make_test_malecule();
        apply_layout(&mut m, LayoutAlgorithm::LayeredSpherical);

        // Central atom should be at origin
        let (x, y, z) = m.atoms[0].position;
        assert!(x.abs() < 0.001 && y.abs() < 0.001 && z.abs() < 0.001);
    }

    #[test]
    fn test_force_directed() {
        let mut m = make_test_malecule();
        apply_layout(&mut m, LayoutAlgorithm::ForceDirected);

        // Should produce non-zero positions
        let has_movement = m.atoms.iter().skip(1).any(|a| {
            let (x, y, z) = a.position;
            x.abs() > 0.001 || y.abs() > 0.001 || z.abs() > 0.001
        });
        assert!(has_movement);
    }

    #[test]
    fn test_hierarchical_tree() {
        let mut m = make_test_malecule();
        apply_layout(&mut m, LayoutAlgorithm::HierarchicalTree);

        // Central atom should be at origin
        let (x, y, z) = m.atoms[0].position;
        assert!(x.abs() < 0.001 && y.abs() < 0.001 && z.abs() < 0.001);
    }

    #[test]
    fn test_spiral_galaxy() {
        let mut m = make_test_malecule();
        apply_layout(&mut m, LayoutAlgorithm::SpiralGalaxy);

        // Central atom should be at origin
        let (x, y, z) = m.atoms[0].position;
        assert!(x.abs() < 0.001 && y.abs() < 0.001 && z.abs() < 0.001);
    }
}
