// +build !windows

/*
 * Copyright (C) 2019 Orange
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy ofthe License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specificlanguage governing permissions and
 * limitations under the License.
 *
 */

package nsm

import (
	"fmt"

	localconn "github.com/networkservicemesh/networkservicemesh/controlplane/pkg/apis/local/connection"
	remoteconn "github.com/networkservicemesh/networkservicemesh/controlplane/pkg/apis/remote/connection"
	"github.com/skydive-project/skydive/filters"
	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/logging"
)

type connection interface {
	addEdge(*graph.Graph)
	delEdge(*graph.Graph)
	getSource() *localconn.Connection
	getDest() *localconn.Connection
	getInodes() (int64, int64)
	createMetadata() graph.Metadata
}

type baseConnectionPair struct {
	payload  string
	srcInode int64
	dstInode int64
	src      *localconn.Connection
	dst      *localconn.Connection
}

func (b *baseConnectionPair) getSource() *localconn.Connection {
	return b.src
}

func (b *baseConnectionPair) getDest() *localconn.Connection {
	return b.dst
}

func (b *baseConnectionPair) getSourceInode() int64 {
	if b.src == nil {
		return 0
	}
	i, err := getLocalInode(b.src)
	if err != nil {
		return 0
	}
	return i
}

func (b *baseConnectionPair) getDestInode() int64 {
	if b.dst == nil {
		return 0
	}
	i, err := getLocalInode(b.dst)
	if err != nil {
		return 0
	}
	return i
}

func (b *baseConnectionPair) getInodes() (int64, int64) {
	return b.getSourceInode(), b.getDestInode()
}

// A local connection is composed of only one cross-connect
type localConnectionPair struct {
	baseConnectionPair
	ID string // crossConnectID
}

// A remote connection is composed of two cross-connects
type remoteConnectionPair struct {
	baseConnectionPair
	remote *remoteconn.Connection // the remote connection shared between the two corss-connects
	srcID  string                 // The id of the cross-connect with a local connection as source
	dstID  string                 // The id of the cross-connect with a local connection as destination

}

// easyjson:json
type baseConnectionMetadata struct {
	MechanismType       string
	MechanismParameters map[string]string
	Labels              map[string]string
}

// easyjson:json
type localConnectionMetadata struct {
	baseConnectionMetadata
	IP string
}

// easyjson:json
type remoteConnectionMetadata struct {
	baseConnectionMetadata
	SourceNSM              string
	DestinationNSM         string
	NetworkServiceEndpoint string
}

// easyjson:json
type baseNSMMetadata struct {
	NetworkService string
	Payload        string
	Source         interface{}
	Destination    interface{}
}

// easyjson:json
type localNSMMetadata struct {
	baseNSMMetadata
	CrossConnectID string
}

// easyjson:json
type remoteNSMMetadata struct {
	baseNSMMetadata
	SourceCrossConnectID      string
	DestinationCrossConnectID string
	Via                       remoteConnectionMetadata
}

func (b *baseConnectionPair) getNodes(g *graph.Graph) (*graph.Node, *graph.Node, error) {
	srcInode, dstInode := b.getInodes()

	if srcInode == 0 || dstInode == 0 {
		// remote connection: src or dst is not ready
		return nil, nil, fmt.Errorf("source or destination inode is not set")
	}

	getNode := func(inode int64) *graph.Node {
		filter := graph.NewElementFilter(filters.NewTermInt64Filter("Inode", inode))
		node := g.LookupFirstNode(filter)
		return node
	}
	// Check that the nodes are in the graph
	srcNode := getNode(srcInode)
	if srcNode == nil {
		return nil, nil, fmt.Errorf("node with inode %d does not exist", srcInode)
	}
	dstNode := getNode(dstInode)
	if dstNode == nil {
		return nil, nil, fmt.Errorf("node with inode %d does not exist", dstInode)
	}

	return srcNode, dstNode, nil

}

func (l *localConnectionPair) addEdge(g *graph.Graph) {
	srcNode, dstNode, err := l.getNodes(g)
	if err != nil {
		logging.GetLogger().Debugf("NSM: cannot create Edge in the graph, %v", err)
		return
	}

	// create Edge
	if !g.AreLinked(srcNode, dstNode, nil) {
		// generate metadatas
		g.Link(srcNode, dstNode, l.createMetadata())
	}
}

func (l *localConnectionPair) delEdge(g *graph.Graph) {
	srcNode, dstNode, err := l.getNodes(g)
	if err != nil {
		logging.GetLogger().Debugf("NSM: cannot delete Edge in the graph, %v", err)
		return
	}

	// delete Edge
	if g.AreLinked(srcNode, dstNode, nil) {
		g.Unlink(srcNode, dstNode)
	}
}

func (l *localConnectionPair) createMetadata() graph.Metadata {
	metadata := graph.Metadata{
		"NSM": localNSMMetadata{
			CrossConnectID: l.ID,
			baseNSMMetadata: baseNSMMetadata{
				Payload:        l.payload,
				NetworkService: l.getSource().GetNetworkService(),
				Source: localConnectionMetadata{
					baseConnectionMetadata: baseConnectionMetadata{
						MechanismType:       l.getSource().GetMechanism().GetType().String(),
						MechanismParameters: l.getSource().GetMechanism().GetParameters(),
						Labels:              l.getSource().GetLabels(),
					},
				},
				Destination: localConnectionMetadata{
					IP: l.getDest().GetContext().GetDstIpAddr(),
					baseConnectionMetadata: baseConnectionMetadata{
						MechanismType:       l.getDest().GetMechanism().GetType().String(),
						MechanismParameters: l.getDest().GetMechanism().GetParameters(),
						Labels:              l.getDest().GetLabels(),
					},
				},
			},
		},
		"Directed": "true",
	}

	return metadata
}

func (r *remoteConnectionPair) addEdge(g *graph.Graph) {
	srcNode, dstNode, err := r.getNodes(g)
	if err != nil {
		logging.GetLogger().Debugf("NSM: cannot create Edge in the graph, %v", err)
		return
	}

	// create Edge
	if !g.AreLinked(srcNode, dstNode, nil) {

		g.Link(srcNode, dstNode, r.createMetadata())
	}
}

func (r *remoteConnectionPair) delEdge(g *graph.Graph) {
	srcNode, dstNode, err := r.getNodes(g)
	if err != nil {
		logging.GetLogger().Debugf("NSM: cannot delete Edge in the graph, %v", err)
		return
	}

	// delete Edge
	if g.AreLinked(srcNode, dstNode, nil) {
		g.Unlink(srcNode, dstNode)
	}
}

func (r *remoteConnectionPair) createMetadata() graph.Metadata {
	metadata := graph.Metadata{
		"NSM": remoteNSMMetadata{
			SourceCrossConnectID:      r.srcID,
			DestinationCrossConnectID: r.dstID,
			baseNSMMetadata: baseNSMMetadata{
				NetworkService: r.getSource().GetNetworkService(),
				Payload:        r.payload,
				Source: localConnectionMetadata{
					IP: r.getSource().GetContext().GetSrcIpAddr(),
					baseConnectionMetadata: baseConnectionMetadata{
						MechanismType:       r.getSource().GetMechanism().GetType().String(),
						MechanismParameters: r.getSource().GetMechanism().GetParameters(),
						Labels:              r.getSource().GetLabels(),
					},
				},
				Destination: localConnectionMetadata{
					IP: r.getDest().GetContext().GetDstIpAddr(),
					baseConnectionMetadata: baseConnectionMetadata{
						MechanismType:       r.getDest().GetMechanism().GetType().String(),
						MechanismParameters: r.getDest().GetMechanism().GetParameters(),
						Labels:              r.getDest().GetLabels(),
					},
				},
			},
			Via: remoteConnectionMetadata{
				baseConnectionMetadata: baseConnectionMetadata{
					MechanismType:       r.remote.GetMechanism().GetType().String(),
					MechanismParameters: r.remote.GetMechanism().GetParameters(),
					Labels:              r.remote.GetLabels(),
				},
				SourceNSM:              r.remote.GetSourceNetworkServiceManagerName(),
				DestinationNSM:         r.remote.GetDestinationNetworkServiceManagerName(),
				NetworkServiceEndpoint: r.remote.GetNetworkServiceEndpointName(),
			},
		},
		"Directed": "true",
	}

	return metadata
}
