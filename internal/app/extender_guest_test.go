package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/nazar256/zyxelctl/internal/router"
)

func TestExtenderGuestWritesAreNeverReplayedOnAuthenticationFailure(t *testing.T) {
	for _, during := range []string{"first PUT", "WLAN check"} {
		t.Run(during, func(t *testing.T) {
			events := []string{}
			writer := &writeRouter{events: &events, retryAuth: true, putErrors: map[int]error{}, wlCheckErrors: map[int]error{}}
			if during == "first PUT" {
				writer.putErrors[1] = router.ErrUnauthenticated
			} else {
				writer.wlCheckErrors[1], writer.wlCheckErrors[2] = router.ErrUnauthenticated, router.ErrUnauthenticated
			}
			application := New(writer, nil, Output{})
			attempted, err := application.applyExtenderIoTModes(context.Background(), writer, map[int]int{3: 1, 7: 1})
			if !errors.Is(err, router.ErrUnauthenticated) {
				t.Fatalf("authentication failure lost: %v", err)
			}
			wantPuts := 1
			if writer.putCalls != wantPuts {
				t.Fatalf("write callback replayed: got %d PUTs, want %d", writer.putCalls, wantPuts)
			}
			if !reflect.DeepEqual(attempted, []int{3}) {
				t.Fatalf("attempted profiles: %v", attempted)
			}
			// Roll back the uncertain first PUT without touching profile 7.
			if _, err := application.applyExtenderIoTModes(context.Background(), writer, map[int]int{3: 0}); err != nil {
				t.Fatal(err)
			}
			if writer.putCalls != wantPuts+1 {
				t.Fatalf("rollback writes replayed: got %d", writer.putCalls)
			}
		})
	}
}

func TestExtenderGuestFinishesEachProfileBeforeNextWrite(t *testing.T) {
	events := []string{}
	writer := &writeRouter{events: &events}
	application := New(writer, nil, Output{})
	if _, err := application.applyExtenderIoTModes(context.Background(), writer, map[int]int{3: 1, 7: 1}); err != nil {
		t.Fatal(err)
	}
	want := []string{"put:/cgi-bin/DAL?oid=wlan", "get:/cgi-bin/Wireless?action=WlCheck", "put:/cgi-bin/DAL?oid=wlan", "get:/cgi-bin/Wireless?action=WlCheck"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("WLAN apply order = %v", events)
	}
}
