.PHONY: pcaps test eval demo

pcaps:                       ## generate the labelled synthetic PCAPs
	python tests/make_pcaps.py

test: pcaps                  ## unit, golden-PCAP and web-layer tests (needs tshark)
	python -m pytest tests -q

eval:                        ## real attack tools vs the sensor, in a virtual lab (Linux, root)
	sudo eval/run_netns_lab.sh

demo:                        ## rebuild the static GitHub Pages demo
	python tools/build_demo.py
