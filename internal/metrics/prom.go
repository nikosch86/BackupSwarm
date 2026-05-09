package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Prom holds the Prometheus registry plus typed counter and gauge handles.
// Counters are monotonic (not reset by LoadAndReset); gauges are populated
// from a SnapshotInput via UpdateFromSnapshot.
type Prom struct {
	registry *prometheus.Registry

	filesBackedUp prometheus.Counter
	chunksStored  prometheus.Counter
	bytesUp       prometheus.Counter
	bytesDown     prometheus.Counter

	peers           *prometheus.GaugeVec
	storeUsed       prometheus.Gauge
	storeCapacity   prometheus.Gauge
	ownBackupFiles  prometheus.Gauge
	ownBackupBytes  prometheus.Gauge
	ownBackupChunks prometheus.Gauge
	replMin         prometheus.Gauge
	replMax         prometheus.Gauge
	replAvg         prometheus.Gauge
}

// SnapshotInput projects the runtime snapshot fields that drive gauges.
// Defined here so internal/metrics never imports internal/daemon.
type SnapshotInput struct {
	PeerStateCounts map[string]int
	StoreUsed       int64
	StoreCapacity   int64
	OwnFiles        int
	OwnBytes        int64
	OwnChunks       int
	ReplMin         int
	ReplMax         int
	ReplAvg         float64
}

// NewProm constructs a Prom with a fresh registry and registers every
// counter, gauge, and standard runtime collector.
func NewProm() *Prom {
	reg := prometheus.NewRegistry()
	p := &Prom{
		registry: reg,
		filesBackedUp: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "backupswarm_files_backed_up_total",
			Help: "Total number of source files successfully backed up.",
		}),
		chunksStored: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "backupswarm_chunks_stored_total",
			Help: "Total number of chunks accepted into the local store on behalf of any owner.",
		}),
		bytesUp: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "backupswarm_bytes_up_total",
			Help: "Total bytes sent over QUIC streams (after rate limiting).",
		}),
		bytesDown: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "backupswarm_bytes_down_total",
			Help: "Total bytes received over QUIC streams.",
		}),
		peers: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "backupswarm_peers",
			Help: "Number of known peers per reachability state.",
		}, []string{"state"}),
		storeUsed: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "backupswarm_store_used_bytes",
			Help: "Bytes currently used by the local chunk store.",
		}),
		storeCapacity: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "backupswarm_store_capacity_bytes",
			Help: "Configured maximum bytes for the local chunk store; 0 means unlimited.",
		}),
		ownBackupFiles: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "backupswarm_own_backup_files",
			Help: "Number of files this node currently has indexed as backed up.",
		}),
		ownBackupBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "backupswarm_own_backup_bytes",
			Help: "Total plaintext byte size across this node's indexed files.",
		}),
		ownBackupChunks: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "backupswarm_own_backup_chunks",
			Help: "Total chunk count across this node's indexed files.",
		}),
		replMin: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "backupswarm_replication_min",
			Help: "Minimum replication count observed across this node's chunks.",
		}),
		replMax: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "backupswarm_replication_max",
			Help: "Maximum replication count observed across this node's chunks.",
		}),
		replAvg: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "backupswarm_replication_avg",
			Help: "Average replication count across this node's chunks.",
		}),
	}
	reg.MustRegister(
		p.filesBackedUp, p.chunksStored, p.bytesUp, p.bytesDown,
		p.peers,
		p.storeUsed, p.storeCapacity,
		p.ownBackupFiles, p.ownBackupBytes, p.ownBackupChunks,
		p.replMin, p.replMax, p.replAvg,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return p
}

// Registry returns the underlying *prometheus.Registry.
func (p *Prom) Registry() *prometheus.Registry { return p.registry }

// FilesBackedUp / ChunksStored / BytesUp / BytesDown return per-event counter handles.
func (p *Prom) FilesBackedUp() prometheus.Counter { return p.filesBackedUp }
func (p *Prom) ChunksStored() prometheus.Counter  { return p.chunksStored }
func (p *Prom) BytesUp() prometheus.Counter       { return p.bytesUp }
func (p *Prom) BytesDown() prometheus.Counter     { return p.bytesDown }

// PeersByState returns the gauge handle for the given reachability state.
func (p *Prom) PeersByState(state string) prometheus.Gauge {
	return p.peers.WithLabelValues(state)
}

// StoreUsed / StoreCapacity / OwnBackup* / Replication* expose gauge handles.
func (p *Prom) StoreUsed() prometheus.Gauge       { return p.storeUsed }
func (p *Prom) StoreCapacity() prometheus.Gauge   { return p.storeCapacity }
func (p *Prom) OwnBackupFiles() prometheus.Gauge  { return p.ownBackupFiles }
func (p *Prom) OwnBackupBytes() prometheus.Gauge  { return p.ownBackupBytes }
func (p *Prom) OwnBackupChunks() prometheus.Gauge { return p.ownBackupChunks }
func (p *Prom) ReplicationMin() prometheus.Gauge  { return p.replMin }
func (p *Prom) ReplicationMax() prometheus.Gauge  { return p.replMax }
func (p *Prom) ReplicationAvg() prometheus.Gauge  { return p.replAvg }

// UpdateFromSnapshot writes s into the gauges. The peers GaugeVec is
// reset before re-population so a state absent from s drops to zero.
func (p *Prom) UpdateFromSnapshot(s SnapshotInput) {
	p.peers.Reset()
	for state, n := range s.PeerStateCounts {
		p.peers.WithLabelValues(state).Set(float64(n))
	}
	p.storeUsed.Set(float64(s.StoreUsed))
	p.storeCapacity.Set(float64(s.StoreCapacity))
	p.ownBackupFiles.Set(float64(s.OwnFiles))
	p.ownBackupBytes.Set(float64(s.OwnBytes))
	p.ownBackupChunks.Set(float64(s.OwnChunks))
	p.replMin.Set(float64(s.ReplMin))
	p.replMax.Set(float64(s.ReplMax))
	p.replAvg.Set(s.ReplAvg)
}
