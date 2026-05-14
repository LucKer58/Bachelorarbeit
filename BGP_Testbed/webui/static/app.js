const sourceSelect = document.getElementById("source");
const targetSelect = document.getElementById("target");
const routeBtn = document.getElementById("route-btn");
const messageEl = document.getElementById("message");
const prefixEl = document.getElementById("prefix");
const pingEl = document.getElementById("ping");
const hijackEl = document.getElementById("hijack");
const pathEl = document.getElementById("path");
const graphEl = document.getElementById("graph");
const scenarioNameEl = document.getElementById("scenario-name");
const scenarioCountsEl = document.getElementById("scenario-counts");
const nodeTitleEl = document.getElementById("node-title");
const nodeDetailsEl = document.getElementById("node-details");

let graphData = null;
let linkSelection = null;
let nodeSelection = null;
let selectedNode = null;
let clickStart = null;

function formatValue(value) {
  if (Array.isArray(value)) {
    return value.length ? value.join(", ") : "-";
  }
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  if (typeof value === "boolean") {
    return value ? "yes" : "no";
  }
  return value;
}

function renderDetailRows(entries) {
  nodeDetailsEl.innerHTML = "";
  entries.forEach(({ label, value }) => {
    if (value === null || value === undefined || value === "") {
      return;
    }
    const row = document.createElement("div");
    row.className = "detail-row";

    const labelEl = document.createElement("span");
    labelEl.className = "detail-label";
    labelEl.textContent = label;

    const valueEl = document.createElement("span");
    valueEl.className = "detail-value";
    valueEl.textContent = formatValue(value);

    row.appendChild(labelEl);
    row.appendChild(valueEl);
    nodeDetailsEl.appendChild(row);
  });
}

function renderNodeDetails(data) {
  const isCensor = data.type === "censor";
  nodeTitleEl.textContent = `${isCensor ? "Censor" : "AS"}: ${data.name}`;

  const entries = [
    { label: "ASN", value: data.asn },
    { label: "Neighbors", value: data.neighbors },
  ];

  if (!isCensor) {
    entries.push(
      { label: "Router ID", value: data.router_id },
      { label: "Prefix", value: data.prefix },
      { label: "RPKI", value: data.rpki_enabled },
      { label: "Tier", value: data.tier }
    );
  } else {
    entries.push(
      { label: "Attack Type", value: data.attack_type },
      { label: "Prefix Hijack Specificity", value: data.prefix_type },
      { label: "Target", value: data.target_router },
      { label: "Prefix", value: data.prefix },
      { label: "Forward Node", value: data.mitm_forward_node },
      { label: "Community", value: data.community },
      { label: "Poison ASN", value: data.poison_asn },
      { label: "Prepend ASN", value: data.prepend_asn },
      { label: "Prepend Count", value: data.prepend_count },
      { label: "Fake Path", value: data.fake_path },
      { label: "Origin Code", value: data.origin_code }
    );
  }

  renderDetailRows(entries);
}

async function fetchNodeDetails(nodeId) {
  if (!nodeId) return;
  nodeTitleEl.textContent = `Loading ${nodeId}...`;
  nodeDetailsEl.innerHTML = "";

  const response = await fetch(`/api/node?name=${encodeURIComponent(nodeId)}`);
  const data = await response.json();
  if (data.error) {
    nodeTitleEl.textContent = data.error;
    return;
  }

  renderNodeDetails(data);
}

function clearNodeDetails() {
  selectedNode = null;
  if (nodeSelection) {
    nodeSelection.classed("selected", false);
  }
  nodeTitleEl.textContent = "Click an AS or censor.";
  nodeDetailsEl.innerHTML = "";
}

function selectNode(nodeId) {
  selectedNode = nodeId;
  if (nodeSelection) {
    nodeSelection.classed("selected", (d) => d.id === nodeId);
  }
  fetchNodeDetails(nodeId);
}

function renderPath(pathNodes) {
  pathEl.innerHTML = "";
  if (!pathNodes || pathNodes.length === 0) {
    pathEl.innerHTML = "<li>No path found</li>";
    return;
  }
  pathNodes.forEach((node) => {
    const li = document.createElement("li");
    li.textContent = node;
    pathEl.appendChild(li);
  });
}

function highlightPath(pathNodes) {
  if (!nodeSelection || !linkSelection) return;

  const pathSet = new Set(pathNodes);
  nodeSelection.classed("highlight", (d) => pathSet.has(d.id));

  const edgeSet = new Set();
  for (let i = 0; i < pathNodes.length - 1; i += 1) {
    const a = pathNodes[i];
    const b = pathNodes[i + 1];
    const key = [a, b].sort().join("--");
    edgeSet.add(key);
  }

  linkSelection.classed("highlight", (d) => {
    const key = [d.source.id || d.source, d.target.id || d.target]
      .sort()
      .join("--");
    return edgeSet.has(key);
  });
}

function buildGraph(data) {
  graphEl.innerHTML = "";
  const width = graphEl.clientWidth;
  const height = graphEl.clientHeight;

  const svg = d3
    .select(graphEl)
    .append("svg")
    .attr("width", width)
    .attr("height", height);

  const simulation = d3
    .forceSimulation(data.nodes)
    .force("link", d3.forceLink(data.links).id((d) => d.id).distance(90))
    .force("charge", d3.forceManyBody().strength(-350))
    .force("center", d3.forceCenter(width / 2, height / 2));

  linkSelection = svg
    .append("g")
    .selectAll("line")
    .data(data.links)
    .join("line")
    .attr("class", "link");

  nodeSelection = svg
    .append("g")
    .selectAll("g")
    .data(data.nodes)
    .join("g")
    .attr("class", (d) => `node ${d.type}`)
    .call(
      d3
        .drag()
        .filter((event) => event.shiftKey)
        .clickDistance(6)
        .on("start", (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on("drag", (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on("end", (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        })
    );

  if (selectedNode) {
    nodeSelection.classed("selected", (d) => d.id === selectedNode);
  }

  nodeSelection
    .on("pointerdown", (event, d) => {
      clickStart = { id: d.id, x: event.clientX, y: event.clientY };
    })
    .on("pointerup", (event) => {
      if (!clickStart) return;
      const dx = event.clientX - clickStart.x;
      const dy = event.clientY - clickStart.y;
      const distance = Math.hypot(dx, dy);
      if (distance <= 6) {
        event.preventDefault();
        event.stopPropagation();
        selectNode(clickStart.id);
      }
      clickStart = null;
    })
    .on("click", (event) => {
      event.stopPropagation();
    });

  svg.on("click", () => {
    clearNodeDetails();
  });

  nodeSelection.append("circle").attr("r", 12);

  nodeSelection
    .append("text")
    .attr("x", 16)
    .attr("y", 4)
    .text((d) => d.id);

  simulation.on("tick", () => {
    linkSelection
      .attr("x1", (d) => d.source.x)
      .attr("y1", (d) => d.source.y)
      .attr("x2", (d) => d.target.x)
      .attr("y2", (d) => d.target.y);

    nodeSelection.attr("transform", (d) => `translate(${d.x},${d.y})`);
  });
}

function populateSelectors(nodes) {
  const routers = nodes.filter((n) => n.type === "router");
  routers.forEach((router) => {
    const opt1 = document.createElement("option");
    opt1.value = router.id;
    opt1.textContent = router.id;
    sourceSelect.appendChild(opt1);

    const opt2 = document.createElement("option");
    opt2.value = router.id;
    opt2.textContent = router.id;
    targetSelect.appendChild(opt2);
  });

  if (routers.length > 1) {
    sourceSelect.value = routers[0].id;
    targetSelect.value = routers[1].id;
  }
}

async function loadTopology() {
  const response = await fetch("/api/topology");
  const data = await response.json();
  if (data.error) {
    messageEl.textContent = data.error;
    return;
  }
  graphData = data;
  buildGraph(data);
  populateSelectors(data.nodes);

  if (data.scenario) {
    const name = data.scenario.name || "-";
    const source = data.scenario.source || "";
    const routers = data.scenario.router_count ?? "-";
    const censors = data.scenario.censor_count ?? "-";
    const scenarioLabel = source || name;
    scenarioNameEl.textContent = `Scenario: ${scenarioLabel}`;
    scenarioCountsEl.textContent = `ASes: ${routers} · Censors: ${censors}`;
  }
}

async function fetchRoute() {
  const source = sourceSelect.value;
  const target = targetSelect.value;
  if (!source || !target) return;

  messageEl.textContent = "Querying route...";

  const response = await fetch(
    `/api/route?source=${encodeURIComponent(source)}&target=${encodeURIComponent(
      target
    )}`
  );
  const data = await response.json();
  if (data.error) {
    messageEl.textContent = data.error;
    return;
  }

  messageEl.textContent = data.message;
  prefixEl.textContent = `Prefix: ${data.used_prefix}`;
  pingEl.textContent = `Ping: ${data.ping_ok ? "ok" : "fail"}`;
  if (data.hijack_active) {
    hijackEl.textContent = `Hijack: ${data.hijack_censor || "active"}`;
  } else {
    hijackEl.textContent = "Hijack: none";
  }

  renderPath(data.path_nodes || []);
  highlightPath(data.path_nodes || []);
}

routeBtn.addEventListener("click", fetchRoute);

window.addEventListener("resize", () => {
  if (graphData) buildGraph(graphData);
});

loadTopology();
