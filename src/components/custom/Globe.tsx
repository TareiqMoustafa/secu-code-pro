import { useEffect, useRef } from 'react';
import * as THREE from 'three';

export default function Globe() {
  const containerRef = useRef<HTMLDivElement>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const frameRef = useRef<number>(0);

  useEffect(() => {
    if (!containerRef.current) return;
    const container = containerRef.current;

    // Scene setup
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, container.offsetWidth / container.offsetHeight, 1, 1000);
    camera.position.z = 200;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(container.offsetWidth, container.offsetHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // Globe group
    const globeGroup = new THREE.Group();
    scene.add(globeGroup);

    // Main wireframe globe
    const sphereGeo = new THREE.SphereGeometry(80, 32, 32);
    const wireframeGeo = new THREE.WireframeGeometry(sphereGeo);
    const wireframeMat = new THREE.LineBasicMaterial({
      color: 0x00f0ff,
      transparent: true,
      opacity: 0.08,
    });
    const wireframe = new THREE.LineSegments(wireframeGeo, wireframeMat);
    globeGroup.add(wireframe);

    // Latitude lines (stronger)
    const latitudesGroup = new THREE.Group();
    for (let i = -4; i <= 4; i++) {
      const lat = (i / 5) * Math.PI * 0.45;
      const radius = Math.cos(lat) * 80;
      const y = Math.sin(lat) * 80;
      const ringGeo = new THREE.RingGeometry(radius - 0.1, radius + 0.1, 64);
      const ringMat = new THREE.MeshBasicMaterial({
        color: 0x00f0ff,
        transparent: true,
        opacity: 0.12,
        side: THREE.DoubleSide,
      });
      const ring = new THREE.Mesh(ringGeo, ringMat);
      ring.position.y = y;
      ring.rotation.x = Math.PI / 2;
      latitudesGroup.add(ring);
    }
    globeGroup.add(latitudesGroup);

    // Inner core (dark sphere)
    const coreGeo = new THREE.SphereGeometry(78, 32, 32);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0x000510,
      transparent: true,
      opacity: 0.8,
    });
    const core = new THREE.Mesh(coreGeo, coreMat);
    globeGroup.add(core);

    // Inner point cloud
    const pointCount = 1500;
    const pointPositions = new Float32Array(pointCount * 3);
    for (let i = 0; i < pointCount; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      const r = 75 + Math.random() * 3;
      pointPositions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      pointPositions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      pointPositions[i * 3 + 2] = r * Math.cos(phi);
    }
    const pointCloudGeo = new THREE.BufferGeometry();
    pointCloudGeo.setAttribute('position', new THREE.BufferAttribute(pointPositions, 3));
    const pointCloudMat = new THREE.PointsMaterial({
      color: 0x00f0ff,
      size: 0.5,
      transparent: true,
      opacity: 0.4,
    });
    const pointCloud = new THREE.Points(pointCloudGeo, pointCloudMat);
    globeGroup.add(pointCloud);

    // Sweeping arcs
    const arcCount = 20;
    interface ArcData {
      mesh: THREE.Mesh;
      angle: number;
      speed: number;
      axis: THREE.Vector3;
    }
    const arcs: ArcData[] = [];
    for (let i = 0; i < arcCount; i++) {
      const curve = new THREE.EllipseCurve(
        0, 0,
        82, 82,
        0, Math.PI * 0.6,
        false,
        0
      );
      const points = curve.getPoints(50);
      const arcGeo = new THREE.BufferGeometry().setFromPoints(
        points.map(p => new THREE.Vector3(p.x, 0, p.y))
      );
      const arcMat = new THREE.LineBasicMaterial({
        color: 0x00f0ff,
        transparent: true,
        opacity: 0.15 + Math.random() * 0.1,
      });
      const arcMesh = new THREE.Line(arcGeo, arcMat);

      const axis = new THREE.Vector3(
        Math.random() - 0.5,
        Math.random() - 0.5,
        Math.random() - 0.5,
      ).normalize();

      arcMesh.lookAt(axis.clone().multiplyScalar(100));
      globeGroup.add(arcMesh);

      arcs.push({
        mesh: arcMesh,
        angle: Math.random() * Math.PI * 2,
        speed: 0.002 + Math.random() * 0.004,
        axis,
      });
    }

    // Scanning nodes
    const nodeCount = 30;
    interface NodeData {
      theta: number;
      phi: number;
      velTheta: number;
      velPhi: number;
      life: number;
      maxLife: number;
    }
    const nodes: NodeData[] = [];
    const nodePositions = new Float32Array(nodeCount * 3);
    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        theta: Math.random() * Math.PI * 2,
        phi: Math.acos(2 * Math.random() - 1),
        velTheta: (Math.random() - 0.5) * 0.02,
        velPhi: (Math.random() - 0.5) * 0.01,
        life: Math.random() * 200,
        maxLife: 200 + Math.random() * 100,
      });
    }
    const nodeGeo = new THREE.BufferGeometry();
    nodeGeo.setAttribute('position', new THREE.BufferAttribute(nodePositions, 3));
    const nodeMat = new THREE.PointsMaterial({
      color: 0x00f0ff,
      size: 2,
      transparent: true,
      opacity: 0.8,
      blending: THREE.AdditiveBlending,
    });
    const nodePoints = new THREE.Points(nodeGeo, nodeMat);
    globeGroup.add(nodePoints);

    // Mouse interaction
    const mouse = { x: 0, y: 0 };
    const targetRotation = { x: 0, y: 0 };
    const handleMouseMove = (e: MouseEvent) => {
      mouse.x = (e.clientX / window.innerWidth - 0.5) * 2;
      mouse.y = (e.clientY / window.innerHeight - 0.5) * 2;
    };
    window.addEventListener('mousemove', handleMouseMove);

    // Animation
    let time = 0;
    const animate = () => {
      frameRef.current = requestAnimationFrame(animate);
      time += 0.01;

      // Rotate globe
      globeGroup.rotation.y += 0.001;
      targetRotation.x = mouse.y * 0.1;
      targetRotation.y = mouse.x * 0.1;
      globeGroup.rotation.x += (targetRotation.x - globeGroup.rotation.x) * 0.02;

      // Animate arcs
      for (const arc of arcs) {
        arc.angle += arc.speed;
        arc.mesh.rotation.z = arc.angle;
      }

      // Animate nodes
      const positions = nodePoints.geometry.attributes.position.array as Float32Array;
      for (let i = 0; i < nodeCount; i++) {
        const node = nodes[i];
        node.theta += node.velTheta;
        node.phi += node.velPhi;
        node.life--;

        if (node.life <= 0) {
          node.theta = Math.random() * Math.PI * 2;
          node.phi = Math.acos(2 * Math.random() - 1);
          node.velTheta = (Math.random() - 0.5) * 0.02;
          node.velPhi = (Math.random() - 0.5) * 0.01;
          node.life = node.maxLife;
        }

        const r = 80;
        const sinPhi = Math.sin(node.phi);
        positions[i * 3] = r * sinPhi * Math.cos(node.theta);
        positions[i * 3 + 1] = r * sinPhi * Math.sin(node.theta);
        positions[i * 3 + 2] = r * Math.cos(node.phi);
      }
      nodePoints.geometry.attributes.position.needsUpdate = true;

      // Pulse point cloud opacity
      pointCloudMat.opacity = 0.3 + Math.sin(time * 2) * 0.1;

      renderer.render(scene, camera);
    };
    animate();

    // Resize handler
    const handleResize = () => {
      const w = container.offsetWidth;
      const h = container.offsetHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(frameRef.current);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('resize', handleResize);
      renderer.dispose();
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, []);

  return (
    <div
      ref={containerRef}
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        zIndex: 1,
        pointerEvents: 'none',
      }}
    />
  );
}
