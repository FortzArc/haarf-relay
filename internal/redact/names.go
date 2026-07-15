package redact

import "strings"

// firstNames is the person_name scrubber's dictionary (lowercased). It is a
// deliberately conservative seed list — common US first names plus the names
// used by the synthetic canary generator — not an attempt at completeness.
// ML-based NER is explicitly out of scope for v0.x (determinism is an audit
// property); operators needing broader name coverage extend this list.
var firstNames = func() map[string]struct{} {
	list := `james mary robert patricia john jennifer michael linda david elizabeth
william barbara richard susan joseph jessica thomas sarah charles karen
christopher lisa daniel nancy matthew betty anthony sandra mark margaret
donald ashley steven kimberly andrew emily paul donna joshua michelle
kenneth carol kevin amanda brian melissa george deborah timothy stephanie
ronald rebecca jason sharon edward laura jeffrey cynthia ryan dorothy
jacob amy gary kathleen nicholas angela eric shirley jonathan anna
stephen brenda larry pamela justin emma scott nicole brandon helen
benjamin samantha samuel katherine gregory christine alexander debra
patrick rachel frank carolyn raymond janet jack maria dennis heather
jerry diane tyler ruth aaron julie jose olivia adam joyce nathan virginia
henry victoria zachary kelly douglas lauren peter christina kyle joan
noah evelyn ethan judith carl megan arthur andrea gerald cheryl roger
hannah keith jacqueline jeremy martha terry gloria lawrence teresa sean
ann austin madison joe kathryn albert abigail jesse sophia willie frances
bryan jean billy alice bruce judy ralph isabella roy julia eugene grace
wayne amber louis denise philip danielle bobby marilyn johnny beverly
maribel thaddeus rosalind casimir odette leopold seraphina ignatius`
	m := make(map[string]struct{}, 256)
	for _, name := range strings.Fields(list) {
		m[name] = struct{}{}
	}
	return m
}()
