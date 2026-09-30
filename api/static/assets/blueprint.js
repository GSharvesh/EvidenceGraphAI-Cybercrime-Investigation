/**
 * blueprint.js — EvidenceGraphAI Cytoscape Threat Blueprint Visualizer
 *
 * Renders interactive attack lifecycle flowcharts for CVE blueprints:
 * - Nodes: Techniques colored by tactic & status (hypothesized/confirmed/refuted)
 * - Edges: Stage transitions labeled with confidence heuristic probabilities
 * - Interactive node inspector with MITRE ATT&CK technique metadata
 */

/* global cytoscape */

class BlueprintVisualizer {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.cy = null;
    this.currentBlueprint = null;
  }

  /**
   * Initializes Cytoscape instance inside container.
   */
  init() {
    if (!this.container || typeof cytoscape === 'undefined') return;

    this.cy = cytoscape({
      container: this.container,
      boxSelectionEnabled: false,
      autounselectify: false,
      style: [
        {
          selector: 'node',
          style: {
            'shape': 'rectangle',
            'background-color': '#0050FF',
            'color': '#FFFFFF',
            'label': 'data(label)',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '11px',
            'font-weight': 'bold',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'text-max-width': '120px',
            'width': '140px',
            'height': '60px',
            'border-width': '3px',
            'border-color': '#000000'
          }
        },
        {
          selector: 'node[status = "confirmed"]',
          style: {
            'background-color': '#C6FF00',
            'color': '#000000',
            'border-color': '#000000'
          }
        },
        {
          selector: 'node[status = "refuted"]',
          style: {
            'background-color': '#FF2E2E',
            'color': '#FFFFFF',
            'border-color': '#000000'
          }
        },
        {
          selector: 'node[tactic = "initial-access"]',
          style: {
            'border-color': '#C6FF00',
            'border-width': '4px'
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 3,
            'line-color': '#C6FF00',
            'target-arrow-color': '#C6FF00',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '10px',
            'color': '#C6FF00',
            'text-background-color': '#1A1A1A',
            'text-background-opacity': 0.9,
            'text-background-padding': '3px',
            'arrow-scale': 1.5
          }
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#FFFFFF',
            'border-width': '5px'
          }
        }
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 40,
        spacingFactor: 1.75
      }
    });

    this.cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      const data = node.data();
      if (typeof window.onBlueprintNodeSelected === 'function') {
        window.onBlueprintNodeSelected(data);
      }
    });
  }

  /**
   * Renders a blueprint object into Cytoscape.
   * @param {Object} blueprint
   */
  render(blueprint) {
    this.currentBlueprint = blueprint;
    if (!this.cy) this.init();
    if (!this.cy || !blueprint) return;

    const elements = [];

    // Root CVE node
    elements.push({
      group: 'nodes',
      data: {
        id: blueprint.cve_id,
        label: `CVE ROOT\n${blueprint.cve_id}`,
        tactic: 'vulnerability',
        status: 'confirmed',
        confidence: 1.0,
        stage: 0
      }
    });

    // Technique nodes
    (blueprint.techniques || []).forEach((t) => {
      elements.push({
        group: 'nodes',
        data: {
          id: t.technique_id,
          label: `${t.technique_id}\n${t.technique_name.slice(0, 16)}`,
          tactic: t.tactic,
          status: t.status || 'hypothesized',
          confidence: t.confidence || 0.85,
          stage: t.stage || 1,
          full_name: t.technique_name,
          rationale: t.rationale
        }
      });
    });

    // Link CVE -> First technique
    if (blueprint.techniques && blueprint.techniques.length > 0) {
      elements.push({
        group: 'edges',
        data: {
          id: `edge-${blueprint.cve_id}-${blueprint.techniques[0].technique_id}`,
          source: blueprint.cve_id,
          target: blueprint.techniques[0].technique_id,
          label: `P=1.00 (exploit)`
        }
      });
    }

    // Transitional EXPECTED_TO_LEAD_TO edges
    (blueprint.edges || []).forEach((e, idx) => {
      const prob = e.probability ? (e.probability * 100).toFixed(0) + '%' : 'hypo';
      elements.push({
        group: 'edges',
        data: {
          id: `edge-${e.from_id}-${e.to_id}-${idx}`,
          source: e.from_id,
          target: e.to_id,
          label: `P=${prob}`
        }
      });
    });

    this.cy.elements().remove();
    this.cy.add(elements);
    this.cy.layout({
      name: 'breadthfirst',
      directed: true,
      padding: 30,
      spacingFactor: 1.5
    }).run();
    this.cy.fit();
  }

  /**
   * Updates node statuses (e.g. after sandbox replay).
   */
  updateStatuses(techniqueResults) {
    if (!this.cy) return;
    (techniqueResults || []).forEach((tr) => {
      const node = this.cy.getElementById(tr.technique_id);
      if (node) {
        node.data('status', tr.status);
      }
    });
  }
}

// Attach globally
window.BlueprintVisualizer = BlueprintVisualizer;
