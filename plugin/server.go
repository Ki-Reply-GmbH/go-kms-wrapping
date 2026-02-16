// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"sync"

	"github.com/openbao/go-kms-wrapping/plugin/v2/pb"
	"github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type gRPCWrapperServer struct {
	pb.UnimplementedWrapperServer

	instances     map[string]wrapping.Wrapper
	instancesLock sync.Mutex

	factory func() wrapping.Wrapper
}

func (ws *gRPCWrapperServer) getInstance(ctx context.Context) (wrapping.Wrapper, error) {
	id, err := pluginutil.GetMultiplexIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	ws.instancesLock.Lock()
	defer ws.instancesLock.Unlock()

	if instance, ok := ws.instances[id]; ok {
		return instance, nil
	}

	// Since factory takes no parameters, just create a new wrapper ad-hoc if we
	// don't have one already.
	instance := ws.factory()
	ws.instances[id] = instance
	return instance, nil
}

func (ws *gRPCWrapperServer) Type(ctx context.Context, req *pb.TypeRequest) (*pb.TypeResponse, error) {
	impl, err := ws.getInstance(ctx)
	if err != nil {
		return nil, err
	}
	typ, err := impl.Type(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.TypeResponse{Type: typ.String()}, nil
}

func (ws *gRPCWrapperServer) KeyId(ctx context.Context, req *pb.KeyIdRequest) (*pb.KeyIdResponse, error) {
	impl, err := ws.getInstance(ctx)
	if err != nil {
		return nil, err
	}
	keyId, err := impl.KeyId(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.KeyIdResponse{KeyId: keyId}, nil
}

func (ws *gRPCWrapperServer) SetConfig(ctx context.Context, req *pb.SetConfigRequest) (*pb.SetConfigResponse, error) {
	impl, err := ws.getInstance(ctx)
	if err != nil {
		return nil, err
	}
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	wc, err := impl.SetConfig(
		ctx,
		wrapping.WithKeyId(opts.WithKeyId),
		wrapping.WithConfigMap(opts.WithConfigMap),
	)
	if err != nil {
		return nil, err
	}
	return &pb.SetConfigResponse{WrapperConfig: wc}, nil
}

func (ws *gRPCWrapperServer) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	impl, err := ws.getInstance(ctx)
	if err != nil {
		return nil, err
	}
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	ct, err := impl.Encrypt(
		ctx,
		req.Plaintext,
		wrapping.WithAad(opts.WithAad),
		wrapping.WithKeyId(opts.WithKeyId),
	)
	if err != nil {
		return nil, err
	}
	return &pb.EncryptResponse{Ciphertext: ct}, nil
}

func (ws *gRPCWrapperServer) Decrypt(ctx context.Context, req *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	impl, err := ws.getInstance(ctx)
	if err != nil {
		return nil, err
	}
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	pt, err := impl.Decrypt(
		ctx,
		req.Ciphertext,
		wrapping.WithAad(opts.WithAad),
		wrapping.WithKeyId(opts.WithKeyId),
	)
	if err != nil {
		return nil, err
	}
	return &pb.DecryptResponse{Plaintext: pt}, nil
}

func (ws *gRPCWrapperServer) Init(ctx context.Context, req *pb.InitRequest) (*pb.InitResponse, error) {
	impl, err := ws.getInstance(ctx)
	if err != nil {
		return nil, err
	}
	initFinalizer, ok := impl.(wrapping.InitFinalizer)
	if !ok {
		return &pb.InitResponse{}, nil
	}
	if err := initFinalizer.Init(ctx); err != nil {
		return nil, err
	}
	return &pb.InitResponse{}, nil
}

func (ws *gRPCWrapperServer) Finalize(ctx context.Context, req *pb.FinalizeRequest) (*pb.FinalizeResponse, error) {
	id, err := pluginutil.GetMultiplexIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	ws.instancesLock.Lock()
	impl, ok := ws.instances[id]
	ws.instancesLock.Unlock()

	// If this instance doesn't exist, just ignore it.
	if !ok {
		return &pb.FinalizeResponse{}, nil
	}

	// Call Finalize if the underlying implementation has it:
	if initFinalizer, ok := impl.(wrapping.InitFinalizer); ok {
		if err := initFinalizer.Finalize(ctx); err != nil {
			return nil, err
		}
	}

	// Then remove the instance:
	ws.instancesLock.Lock()
	delete(ws.instances, id)
	ws.instancesLock.Unlock()

	return &pb.FinalizeResponse{}, nil
}

func (ws *gRPCWrapperServer) KeyBytes(ctx context.Context, req *pb.KeyBytesRequest) (*pb.KeyBytesResponse, error) {
	impl, err := ws.getInstance(ctx)
	if err != nil {
		return nil, err
	}
	keyExporter, ok := impl.(wrapping.KeyExporter)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this Wrapper does not implement KeyExporter")
	}
	keyBytes, err := keyExporter.KeyBytes(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.KeyBytesResponse{KeyBytes: keyBytes}, nil
}
