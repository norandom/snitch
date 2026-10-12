package main

import "testing"

func TestStatusDNSLineFromRecord(t *testing.T) {
	f := newFake(nil)
	f.rec = fullRecord
	for _, value := range []string{"on seen 42 ignored 10 cache 1 names 2 compiled 1", "off: flag"} {
		f.rec.DNS = value
		code, out, errw := f.run(t, "status")
		if code != 0 || errw != "" || line(out, "dns:") != "dns:       "+value {
			t.Fatalf("exit %d stderr %q output %s", code, errw, out)
		}
	}
	f.rec.DNS = ""
	_, out, _ := f.run(t, "status")
	if line(out, "dns:") != "" {
		t.Fatal(out)
	}
}
