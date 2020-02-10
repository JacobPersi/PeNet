﻿using System.Linq;
using PeNet.Parser;
using PeNet.Structures;
using PeNet.Utilities;

namespace PeNet
{
    internal class DotNetStructureParsers
    {
        private readonly byte[] _buff;
        private readonly IMAGE_SECTION_HEADER[]? _sectionHeaders;
        private readonly IMAGE_COR20_HEADER? _imageCor20Header;
        private readonly MetaDataHdrParser? _metaDataHdrParser;
        private readonly MetaDataStreamStringParser? _metaDataStreamStringParser;
        private readonly MetaDataStreamUSParser? _metaDataStreamUSParser;
        private readonly MetaDataStreamTablesHeaderParser? _metaDataStreamTablesHeaderParser;
        private readonly MetaDataStreamGUIDParser? _metaDataStreamGuidParser;
        private readonly MetaDataStreamBlobParser? _metaDataStreamBlobParser;

        public METADATAHDR? MetaDataHdr => _metaDataHdrParser?.GetParserTarget();
        public IMETADATASTREAM_STRING? MetaDataStreamString => _metaDataStreamStringParser?.GetParserTarget();
        public IMETADATASTREAM_US? MetaDataStreamUS => _metaDataStreamUSParser?.GetParserTarget();
        public IMETADATASTREAM_GUID? MetaDataStreamGUID => _metaDataStreamGuidParser?.GetParserTarget();
        public byte[]? MetaDataStreamBlob => _metaDataStreamBlobParser?.GetParserTarget();
        public METADATATABLESHDR? MetaDataStreamTablesHeader => _metaDataStreamTablesHeaderParser?.GetParserTarget();

        public DotNetStructureParsers(
            byte[] buff,
            IMAGE_COR20_HEADER? imageCor20Header,
            IMAGE_SECTION_HEADER[]? sectionHeaders)
        {
            _buff = buff;
            _sectionHeaders = sectionHeaders;
            _imageCor20Header = imageCor20Header;

            // Init all parsers
            _metaDataHdrParser = InitMetaDataParser();
            _metaDataStreamStringParser = InitMetaDataStreamStringParser();
            _metaDataStreamUSParser = InitMetaDataStreamUSParser();
            _metaDataStreamTablesHeaderParser = InitMetaDataStreamTablesHeaderParser();
            _metaDataStreamGuidParser = InitMetaDataStreamGUIDParser();
            _metaDataStreamBlobParser = InitMetaDataStreamBlobParser();
        }

        private MetaDataHdrParser? InitMetaDataParser()
        {
            var rawAddress = _imageCor20Header?.MetaData?.VirtualAddress.SafeRVAtoFileMapping(_sectionHeaders);
            return rawAddress == null ? null : new MetaDataHdrParser(_buff, rawAddress.Value);
        }

        private MetaDataStreamStringParser? InitMetaDataStreamStringParser()
        {
            var metaDataStream = MetaDataHdr?.MetaDataStreamsHdrs?.FirstOrDefault(x => x.streamName == "#Strings");

            return metaDataStream == null 
                ? null 
                : new MetaDataStreamStringParser(_buff, MetaDataHdr!.Offset + metaDataStream.offset, metaDataStream.size);
        }

        private MetaDataStreamUSParser? InitMetaDataStreamUSParser()
        {
            var metaDataStream = MetaDataHdr?.MetaDataStreamsHdrs?.FirstOrDefault(x => x.streamName == "#US");

            return metaDataStream == null 
                ? null 
                : new MetaDataStreamUSParser(_buff, MetaDataHdr!.Offset + metaDataStream.offset, metaDataStream.size);
        }

        private MetaDataStreamTablesHeaderParser? InitMetaDataStreamTablesHeaderParser()
        {
            var metaDataStream = MetaDataHdr?.MetaDataStreamsHdrs?.FirstOrDefault(x => x.streamName == "#~");

            return metaDataStream == null 
                ? null 
                : new MetaDataStreamTablesHeaderParser(_buff, MetaDataHdr!.Offset + metaDataStream.offset);
        }

        private MetaDataStreamGUIDParser? InitMetaDataStreamGUIDParser()
        {
            var metaDataStream = MetaDataHdr?.MetaDataStreamsHdrs?.FirstOrDefault(x => x.streamName == "#GUID");

            return metaDataStream == null 
                ? null 
                : new MetaDataStreamGUIDParser(_buff, MetaDataHdr!.Offset +  metaDataStream.offset, metaDataStream.size);
        }

        private MetaDataStreamBlobParser? InitMetaDataStreamBlobParser()
        {
            var metaDataStream = MetaDataHdr?.MetaDataStreamsHdrs?.FirstOrDefault(x => x.streamName == "#Blob");

            return metaDataStream == null 
                ? null 
                : new MetaDataStreamBlobParser(_buff, MetaDataHdr!.Offset + metaDataStream.offset, metaDataStream.size);
        }
    }
}