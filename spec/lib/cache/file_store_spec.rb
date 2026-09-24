# frozen_string_literal: true

describe WPScan::Cache::FileStore do
  subject(:cache) { described_class.new(storage_path, serializer) }

  let(:storage_path) { Dir.mktmpdir }
  let(:serializer)   { Marshal }
  let(:key)          { 'key' }

  after { FileUtils.rm_rf(storage_path) }

  describe '#write_entry' do
    context 'when the data can be dumped' do
      it 'stores it' do
        cache.write_entry(key, 'data', 60)

        expect(cache.read_entry(key)).to eql 'data'
      end
    end

    context 'when the data is too big to dump' do
      # Stubbed: reproducing it takes a String of 2GiB or more
      before { allow(serializer).to receive(:dump).and_raise(TypeError, 'long too big to dump') }

      it 'does not raise nor store anything' do
        expect { cache.write_entry(key, 'data', 60) }.not_to raise_error

        expect(Dir.children(storage_path)).to be_empty
      end
    end

    context 'when the data cannot be dumped for another reason' do
      it 'raises' do
        expect { cache.write_entry(key, proc {}, 60) }.to raise_error(TypeError, /no _dump_data/)
      end
    end
  end
end
