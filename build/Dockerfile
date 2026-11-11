ARG RUN_FROM=gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

FROM ${RUN_FROM} as image

COPY output/bin/vmware-avi-connector /bin
COPY manifest.json /bin

USER nonroot:nonroot

ENTRYPOINT [ "/bin/vmware-avi-connector" ]
